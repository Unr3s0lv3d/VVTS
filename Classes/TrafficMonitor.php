<?php

namespace VVTS\Classes;

require_once(dirname(__FILE__) . "/../autoload.php");
require_once(dirname(__FILE__) . "/../external/phpqrcode/qrlib.php");

use \VVTS\Classes\MainLoop;
use \VVTS\Classes\MiscNet;
use \VVTS\Classes\HttpClient;
use \VVTS\Classes\ScriptEngine;
use \VVTS\Classes\Subscribable;
use \VVTS\Types\ScriptInvokeError;
use \VVTS\Types\ScriptVoid;
use \VVTS\Types\ScriptState;
use \VVTS\Types\ScriptStringLiteral;
use \VVTS\Types\VpnEndpointDescriptor;
use \VVTS\Interfaces\IUnblockable;
use \VVTS\Interfaces\IScriptOpaque;
use \QRcode;

define("ANSI_RESET", "\x1B[0m");
define("ANSI_BLACKONGREY", "\x1B[30;47;27m");
define("UTF8_BOTH", "\xE2\x96\x88");
define("UTF8_TOPHALF", "\xE2\x96\x80");
define("UTF8_BOTTOMHALF", "\xE2\x96\x84");

define("MONITOR_CREATE_TOKEN", 0);
define("MONITOR_QUERY", 1);

class TrafficMonitor implements IUnblockable, IScriptOpaque {
    var $szInterface;
    var $hProcess;
    var $hProcessStdout;
    var $hProcessStderr;
    var $aTransitions;
    var $oHttpClient;
    var $bMonitorSecure;
    var $szMonitorHost;
    var $wMonitorPort;
    var $szMonitorUri;
    var $aMonitorAddresses;
    var $aVpnEndpoints;
    var $szToken;
    var $dwMonitorState;
    var $bEndpointTrafficDetected;
    var $bDirectTrafficDetected;
    var $dwDelayTime;

    function __construct() {
        $this->aMonitorAddresses = [];
        $this->aVpnEndpoints = [];
        $this->aTransitions = [];
        $this->bEndpointTrafficDetected = false;
        $this->bDirectTrafficDetected = false;

        MainLoop::GetInstance()->RegisterObject($this);
    }

    function Sockets() {
        $aStreams = [];
        if ($this->hProcessStdout != null) {
            array_push($aStreams, $this->hProcessStdout);
        }
        if ($this->hProcessStderr != null) {
            array_push($aStreams, $this->hProcessStderr);
        }
        return $aStreams;
    }

    function EnterStateDelayHelper($oTransition) {
        ScriptEngine::GetInstance()->EnterState($oTransition);
    }

    function PerformTransition($szWhich, $dwDelayTime = null) {
        if (isset($this->aTransitions[$szWhich])) {
            $oTransition = $this->aTransitions[$szWhich];
            $this->aTransitions = [];
            $this->Teardown();
            if ($dwDelayTime === null) {
                ScriptEngine::GetInstance()->EnterState($oTransition);
            } else {
                MainLoop::GetInstance()->RegisterTimer($this, "EnterStateDelayHelper", $oTransition, $dwDelayTime);
            }
        }
    }

    function Onunblock($hStream) {
        if ($hStream === $this->hProcessStdout) {
            $abLength = fread($this->hProcessStdout, 2);
            if ($abLength === "" || $abLength === false) {
_process_exit:
                printf("[i] trafficmonitor process exited\n");
                fclose($this->hProcessStdout);
                $this->hProcessStdout = null;
                fclose($this->hProcessStderr);
                $this->hProcessStderr = null;
                proc_close($this->hProcess);
                $this->hProcess = null;

                ScriptEngine::GetInstance()->SetErrstr("trafficmonitor process exited (interface down?)");
                $this->Teardown();
                $this->PerformTransition("error");
                return;
            }
            $wLength = (ord($abLength[0]) << 8) | ord($abLength[1]);
            $abPacket = "";
            while(strlen($abPacket) !== $wLength) {
                $abBuf = fread($this->hProcessStdout, $wLength - strlen($abPacket));
                if ($abBuf === "" || $abBuf === false) {
                    goto _process_exit;
                }
                $abPacket .= $abBuf;
            }
            if (strlen($abPacket) < 20) {
                goto _skip;
            }
            $bVersion = ord($abPacket[0]) >> 4;
            if ($bVersion === 4) {
                /* ipv4 frame */
                $bProto = ord($abPacket[9]);
                $wHeaderLength = (ord($abPacket[0]) & 0xf) << 2;
                $wFragmentOffset = ((ord($abPacket[6]) << 8) | ord($abPacket[7])) & 0x1fff;
                if (/*$bProto != 6 ||*/ $wFragmentOffset != 0 || strlen($abPacket) < $wHeaderLength + 4) {
                    goto _skip;
                }
                /* oSrcAddr and oDstAddr are dwords but we use 'o' prefix for opaque types */
                $oSrcAddr = (ord($abPacket[12]) << 24) | (ord($abPacket[13]) << 16) | (ord($abPacket[14]) << 8) | ord($abPacket[15]);
                $oDstAddr = (ord($abPacket[16]) << 24) | (ord($abPacket[17]) << 16) | (ord($abPacket[18]) << 8) | ord($abPacket[19]);
                /* the values below don't mean anything for protocols other than TCP (6) or UDP (17) */
                $wSrcPort = (ord($abPacket[$wHeaderLength]) << 8) | ord($abPacket[$wHeaderLength+1]);
                $wDstPort = (ord($abPacket[$wHeaderLength+2]) << 8) | ord($abPacket[$wHeaderLength+3]);
            } else if ($bVersion === 6) {
                /* ipv6 frame */
                $bProto = ord($abPacket[6]);
                $wPayloadLength = (ord($abPacket[4]) << 8) | ord($abPacket[5]);
                /*
                 * tgere's no fragment size in the ipv6 header, it needs a designated additional fragment header
                 * which linux doesn't even seem to ever send so we don't bother
                 */
                if ($wPayloadLength < 4 || strlen($abPacket) < 44) {
                    goto _skip;
                }
                /* oSrcAddr and oDstAddr are binary strings but we use 'o' prefix for opaque types */
                $oSrcAddr = substr($abPacket, 8, 16);
                $oDstAddr = substr($abPacket, 24, 16);
                /* the values below don't mean anything for protocols other than TCP (6) or UDP (17) */
                $wSrcPort = (ord($abPacket[40]) << 8) | ord($abPacket[41]);
                $wDstPort = (ord($abPacket[42]) << 8) | ord($abPacket[43]);
            } else {
                goto _skip;
            }

            if (!$this->bDirectTrafficDetected && ($bProto === 6 || $bProto === 17)) {
                /*
                 * here we detect whether traffic flows directly, outside of the vpn tunnel
                 * only tcp (6) and udp (17) are valid because the victim sends a request
                 * over http or quic to the validation server
                 */
                foreach($this->aMonitorAddresses as $szMonitorAddress) {
                    if ((
                        ($bVersion === 4 && ($oMonitorAddress = MiscNet::Ipv4StringToDword($szMonitorAddress)) !== false) ||
                        ($bVersion === 6 && ($oMonitorAddress = MiscNet::Ipv6StringToBinary($szMonitorAddress)) !== false) ||
                        ($bVersion === 6 && ($oMonitorAddress = MiscNet::Ipv4ToNat64(MiscNet::Ipv4StringToDword($szMonitorAddress))) !== false)
                    ) && (
                        ($oSrcAddr === $oMonitorAddress && $wSrcPort === $this->wMonitorPort) ||
                        ($oDstAddr === $oMonitorAddress && $wDstPort === $this->wMonitorPort)
                    )) {
                        printf("[!] traffic monitor detected traffic flowing outside of tunnel\n");
                        printf("    src=%s:%d dst=%s:%d\n",
                            ($bVersion === 4) ? MiscNet::DwordToIpv4String($oSrcAddr) : "[".MiscNet::BinaryToIpv6String($oSrcAddr)."]", $wSrcPort,
                            ($bVersion === 4) ? MiscNet::DwordToIpv4String($oDstAddr) : "[".MiscNet::BinaryToIpv6String($oDstAddr)."]", $wDstPort,
                        );
                        $this->bDirectTrafficDetected = true;
                        break;
                    }
                }
            }

            if (!$this->bEndpointTrafficDetected) {
                /*
                 * here we detect whether vpn traffic flows through our setup
                 * mostly to prevent user error and rule out the scenario where the user is not using vpn at all
                 * or connects to our validation server via other means than our setup
                 */
                foreach($this->aVpnEndpoints as $oEndpoint) {
                    if ((
                        ($bVersion === 4 && ($oEndpointAddress = MiscNet::Ipv4StringToDword($oEndpoint->szHostname)) !== false) ||
                        ($bVersion === 6 && ($oEndpointAddress = MiscNet::Ipv6StringToBinary($oEndpoint->szHostname)) !== false) ||
                        ($bVersion === 6 && ($oEndpointAddress = MiscNet::Ipv4ToNat64(MiscNet::Ipv4StringToDword($oEndpoint->szHostname))) !== false)
                    ) && (
                        $bProto === $oEndpoint->bProtocol && ((
                            $oEndpoint->wPort === null && (
                                $oSrcAddr === $oEndpointAddress ||
                                $oDstAddr === $oEndpointAddress
                            )
                        ) || (
                            $oEndpoint->wPort != null && (
                                ($oSrcAddr === $oEndpointAddress && $wSrcPort === $oEndpoint->wPort) ||
                                ($oDstAddr === $oEndpointAddress && $wDstPort === $oEndpoint->wPort)
                            )
                        ))
                    )) {
                        printf("[!] traffic monitor detected vpn traffic going to endpoint\n");
                        if ($bProto === 6 || $bProto === 17) {
                            printf("    proto=%s src=%s:%d dst=%s:%d\n",
                                ($bProto === 6) ? "tcp" : "udp",
                                ($bVersion === 4) ? MiscNet::DwordToIpv4String($oSrcAddr) : "[".MiscNet::BinaryToIpv6String($oSrcAddr)."]", $wSrcPort,
                                ($bVersion === 4) ? MiscNet::DwordToIpv4String($oDstAddr) : "[".MiscNet::BinaryToIpv6String($oDstAddr)."]", $wDstPort,
                            );
                        } else {
                            printf("    proto=%s src=%s dst=%s\n",
                                ($bProto === 47) ? "gre" : (($bProto === 50) ? "ipsec" : "l2tp"),
                                ($bVersion === 4) ? MiscNet::DwordToIpv4String($oSrcAddr) : "[".MiscNet::BinaryToIpv6String($oSrcAddr)."]",
                                ($bVersion === 4) ? MiscNet::DwordToIpv4String($oDstAddr) : "[".MiscNet::BinaryToIpv6String($oDstAddr)."]",
                            );
                        }
                        $this->bEndpointTrafficDetected = true;
                        $this->PerformTransition("vpn_detected", $this->dwDelayTime);
                        break;
                    }
                }
            }
_skip:
        } else if ($hStream === $this->hProcessStderr) {
            $abBuf = fgets($this->hProcessStderr, 1024);
            printf("[i] trafficmonitor: %s", $abBuf);
        }
    }

    function PrintQrCode($szData) {
        $aQrcode = QRcode::text($szData);
        $dwNumLines = count($aQrcode);

        for($y = -1; $y < $dwNumLines+1; $y+=2) {
            printf(" %s", ANSI_BLACKONGREY);
            for ($x = 0; $x < strlen($aQrcode[0]); $x++) {
                $bTop = isset($aQrcode[$y]) ? ($aQrcode[$y][$x] == '1') : true;
                $bBottom = isset($aQrcode[$y+1]) ? ($aQrcode[$y+1][$x] == '1') : true;

                if ($bTop && $bBottom) {
                    printf("%s", UTF8_BOTH);
                } else if ($bTop) {
                    printf("%s", UTF8_TOPHALF);
                } else if ($bBottom) {
                    printf("%s", UTF8_BOTTOMHALF);
                } else {
                    printf(" ");
                }
            }
            printf("%s\n", ANSI_RESET);
        }
    }

    function OnHttpError($szErrstr) {
        if ($this->oHttpClient !== null) {
            $this->oHttpClient->CancelAllSubscriptions();
        }

        ScriptEngine::GetInstance()->SetErrstr("http error: " . $szErrstr);
        $this->Teardown();
        $this->PerformTransition("error");
    }

    function OnHttpResponse($szBody) {
        if ($this->oHttpClient !== null) {
            $this->oHttpClient->CancelAllSubscriptions();
        }
        $oJson = @json_decode($szBody);

        if (is_object($oJson)) {
            if ($this->dwMonitorState == MONITOR_CREATE_TOKEN) {
                $this->szToken = $oJson->token;
                $this->dwMonitorState = MONITOR_QUERY;

                $szUrl = sprintf("http%s://%s%s%s?flag=%s",
                    $this->bMonitorSecure ? "s" : "",
                    $this->szMonitorHost,
                    ($this->bMonitorSecure && $this->wMonitorPort == 443) || (!$this->bMonitorSecure && $this->wMonitorPort == 80) ? "" : ":" . $this->wMonitorPort,
                    $this->szMonitorUri,
                    urlencode($this->szToken)
                );
                printf("[i] please visit %s on the victim device\n", $szUrl);
                $this->PrintQrCode($szUrl);
            } else if (isset($oJson->flagged)) {
                if ($oJson->flagged === "FLAGGED") {
                    if (isset($oJson->ip) && $oJson->ip !== null) {
                        printf("[i] validation server was contacted from IP: %s\n", $oJson->ip);
                    }
                    if ($this->bDirectTrafficDetected) {
                        ScriptEngine::GetInstance()->SetErrstr("[!] direct traffic detected");
                        if (count($this->aVpnEndpoints) === 0) {
                            printf("[!] WARNING: no endpoints defined, cannot confirm that vpn traffic has occurred\n");
                        }
                        if (count($this->aVpnEndpoints) > 0 && !$this->bEndpointTrafficDetected) {
                            ScriptEngine::GetInstance()->SetErrstr("[-] validation server was contacted directly, but no vpn traffic seems to have occurred (forgot to enable vpn client?)");
                            $this->PerformTransition("error");
                        } else {
                            $this->PerformTransition("vulnerable");
                        }
                        return;
                    } else if ($this->bEndpointTrafficDetected || count($this->aVpnEndpoints) === 0) {
                        if (count($this->aVpnEndpoints) === 0) {
                            printf("[!] WARNING: no endpoints defined, cannot confirm that vpn traffic has occurred\n");
                        }
                        $this->PerformTransition("safe");
                        return;
                    } else {
                        ScriptEngine::GetInstance()->SetErrstr("[-] validation server was contacted through other means than vpn or direct");
                        $this->Teardown();
                        $this->PerformTransition("error");
                        return;
                    }
                }
            }
        }

        MainLoop::GetInstance()->RegisterTimer($this, "MonitorSendRequest", null, 1000);
        return;
    }

    function Teardown() {
        if ($this->hProcessStdout != null) {
            fclose($this->hProcessStdout);
            $this->hProcessStdout = null;
        }
        if ($this->hProcessStderr != null) {
            fclose($this->hProcessStderr);
            $this->hProcessStderr = null;
        }
        if ($this->hProcess != null) {
            $aStatus = proc_get_status($this->hProcess);
            if (isset($aStatus["running"]) && $aStatus["running"]) {
                posix_kill($aStatus["pid"], SIGTERM);
            }
            proc_close($this->hProcess);
            $this->hProcess = null;
        }
        $this->bEndpointTrafficDetected = false;
        $this->bDirectTrafficDetected = false;
        MainLoop::GetInstance()->CancelTimer($this, "MonitorSendRequest", null);
    }

    function StateMachineSet_interface($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("interface must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->szInterface = null;
        } else {
            $this->szInterface = $oValue->szLiteral;
        }
    }

    function StateMachineSet_vpn_endpoints($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("vpn_endpoints must be of type string");
        }

        $aSplit = explode(';', $oValue->szLiteral);

        foreach($aSplit as $szValue) {
            if (empty($szValue)) {
                continue;
            }
            $oEndpoint = VpnEndpointDescriptor::FromString($szValue);
            if ($oEndpoint === null) {
                throw new ScriptInvokeError("could not parse vpn endpoint " . $szValue);
            }
            if (MiscNet::Ipv4StringToDword($oEndpoint->szHostname) !== false ||
                MiscNet::Ipv6StringToBinary($oEndpoint->szHostname) !== false
            ) {
                printf("[i] adding endpoint %s\n", $oEndpoint->ToString());
                array_push($this->aVpnEndpoints, $oEndpoint);
            } else if (is_array(($aLookupResult = dns_get_record($oEndpoint->szHostname, DNS_A | DNS_AAAA)))) {
                foreach($aLookupResult as $oResult) {
                    if ($oResult["type"] === "A") {
                        $oEndpointResolved = new VpnEndpointDescriptor($oEndpoint->bProtocol, $oResult["ip"], $oEndpoint->wPort);
                    } else if ($oResult["type"] === "AAAA") {
                        $oEndpointResolved = new VpnEndpointDescriptor($oEndpoint->bProtocol, $oResult["ipv6"], $oEndpoint->wPort);
                    } else {
                        continue;
                    }
                    printf("[i] adding endpoint %s\n", $oEndpointResolved->ToString());
                    array_push($this->aVpnEndpoints, $oEndpointResolved);
                }
            } else {
                throw new ScriptInvokeError("could not resolve address " . $oEndpoint->szHostname);
            }
        }
    }

    function StateMachineSet_validation_server($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("validation_server must be of type string");
        }

        if (!preg_match('/^http(s)?:\/\/(\[[0-9a-f:\.]+\]|[^:@\/\s]+)(?::([0-9]+))?(\/[^?]*)$/', $oValue->szLiteral, $aMatchUrl)) {
            throw new ScriptInvokeError("invalid format for validation_server: " . $oValue->szLiteral);
        }

        $this->bMonitorSecure = $aMatchUrl[1] === "s";
        $this->szMonitorHost = $aMatchUrl[2];
        if (
            $this->szMonitorHost[0] === '[' && $this->szMonitorHost[strlen($this->szMonitorHost)-1] === ']' &&
            MiscNet::Ipv6StringToBinary(substr($this->szMonitorHost, 1, strlen($this->szMonitorHost)-2)) !== false
        ) {
            $this->szMonitorHost = substr($this->szMonitorHost, 1, strlen($this->szMonitorHost)-2);
        }
        $this->wMonitorPort = $aMatchUrl[3] === "" ? ($this->bMonitorSecure ? 443 : 80) : intval($aMatchUrl[3]);
        $this->szMonitorUri = $aMatchUrl[4];
        $this->aMonitorAddresses = [];

        if (MiscNet::Ipv4StringToDword($this->szMonitorHost) !== false ||
            MiscNet::Ipv6StringToBinary($this->szMonitorHost) !== false
        ) {
            array_push($this->aMonitorAddresses, $this->szMonitorHost);
        } else if (is_array(($aLookupResult = dns_get_record($this->szMonitorHost, DNS_A | DNS_AAAA)))) {
            $bEmptyLookupResult = true;
            foreach($aLookupResult as $oResult) {
                if ($oResult["type"] === "A") {
                    $szResolved = $oResult["ip"];
                } else if ($oResult["type"] === "AAAA") {
                    $szResolved = $oResult["ipv6"];
                } else {
                    continue;
                }
                array_push($this->aMonitorAddresses, $szResolved);
                $bEmptyLookupResult = false;
            }
            if ($bEmptyLookupResult) {
                goto _no_results;
            }
        } else {
_no_results:
            throw new ScriptInvokeError("could not resolve address " . $this->szMonitorHost);
        }
    }

    function MonitorSendRequest() {
        if ($this->oHttpClient === null) {
            $this->oHttpClient = new HttpClient($this->szMonitorHost, $this->wMonitorPort, $this->bMonitorSecure);
        }

        if ($this->dwMonitorState == MONITOR_CREATE_TOKEN) {
            $szUri = $this->szMonitorUri . "?create_token";
        } else {
            $szUri = $this->szMonitorUri . "?query=" . urlencode($this->szToken);
        }
        $this->oHttpClient->Subscribe("http_response", $this, "OnHttpResponse", null, true);
        $this->oHttpClient->Subscribe("http_error", $this, "OnHttpError", null, true);
        $this->oHttpClient->SendRequest($szUri, 2000);
    }

    function InitMonitorProcess() {
        if ($this->hProcess !== null) {
            return;
        }

        $aSpec = [
            0 => ["file", "/dev/null", "r"],
            1 => ["pipe", "w"],
            2 => ["pipe", "w"]
        ];

        $this->hProcess = proc_open("exec " . escapeshellarg(dirname(__FILE__) . "/../src/trafficmonitor") . " " . escapeshellarg($this->szInterface), $aSpec, $aPipes);
        $this->hProcessStdout = $aPipes[1];
        $this->hProcessStderr = $aPipes[2];
    }

    function StateMachineInvoke_detect_vpn(...$aArguments) {
        if (count($aArguments) != 2 && count($aArguments) != 3) {
            throw new ScriptInvokeError("detect_vpn requires two arguments");
        } else if (!($aArguments[0] instanceof ScriptState) || !($aArguments[1] instanceof ScriptState)) {
            throw new ScriptInvokeError("detect_vpn requires a vpn_detected and an error state as parameters, respectively");
        } else if (count($aArguments) == 3 && !($aArguments[2] instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("timeout argument must be of type string");
        } else if ($this->szInterface === null) {
            throw new ScriptInvokeError("Please set interface before invoking detect_vpn()");
        } else if (!is_array($this->aVpnEndpoints) || count($this->aVpnEndpoints) == 0) {
            throw new ScriptInvokeError("Please set vpn_endpoints before invoking detect_vpn()");
        }

        $oDetectedState = $aArguments[0];
        $oErrorState = $aArguments[1];
        $dwDelayTime = isset($aArguments[2]) ? intval($aArguments[2]->szLiteral) : null;
        $this->aTransitions["vpn_detected"] = ScriptEngine::GetInstance()->RegisterStateTransition($oDetectedState);
        $this->aTransitions["error"] = ScriptEngine::GetInstance()->RegisterStateTransition($oErrorState);
        $this->dwDelayTime = $dwDelayTime;

        $this->InitMonitorProcess();
        return new ScriptVoid();
    }

    function StateMachineInvoke_detect_attack(...$aArguments) {
        if (count($aArguments) != 3) {
            throw new ScriptInvokeError("detect_attack requires three arguments");
        } else if (!($aArguments[0] instanceof ScriptState) || !($aArguments[1] instanceof ScriptState) || !($aArguments[2] instanceof ScriptState)) {
            throw new ScriptInvokeError("detect_attack requires a safe, vulnerable and error state as parameters, respectively");
        } else if ($this->szInterface === null) {
            throw new ScriptInvokeError("Please set interface before invoking detect_attack()");
        } else if (!is_array($this->aMonitorAddresses) || count($this->aMonitorAddresses) == 0) {
            throw new ScriptInvokeError("Please set validation_server before invoking detect_attack()");
        }

        list ($oSafeState, $oVulnerableState, $oErrorState) = $aArguments;
        $this->aTransitions["safe"] = ScriptEngine::GetInstance()->RegisterStateTransition($oSafeState);
        $this->aTransitions["vulnerable"] = ScriptEngine::GetInstance()->RegisterStateTransition($oVulnerableState);
        $this->aTransitions["error"] = ScriptEngine::GetInstance()->RegisterStateTransition($oErrorState);

        $this->szToken = null;
        $this->dwMonitorState = MONITOR_CREATE_TOKEN;
        $this->MonitorSendRequest();
        $this->InitMonitorProcess();
        return new ScriptVoid();
    }
}

?>