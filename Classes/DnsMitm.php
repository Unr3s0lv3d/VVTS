<?php

namespace VVTS\Classes;

require_once(dirname(__FILE__) . "/../autoload.php");

use \VVTS\Classes\MainLoop;
use \VVTS\Classes\MiscNet;
use \VVTS\Classes\Subscribable;
use \VVTS\Interfaces\IUnblockable;
use \VVTS\Types\DnsTransactionMapEntry;

class DnsMitm extends Subscribable implements IUnblockable {
    var $hListeningSocket;
    var $hClientSocket;
    var $szNextDns;
    var $aTransactionMap;
    var $aOverridesA;
    var $aOverridesAAAA;
    var $dwBindAddr;
    var $abBindIpv6Addr;
    var $szCatchAllAddress;

    function __construct() {
        parent::__construct();
        $this->aTransactionMap = [];
        $this->aOverridesA = [];
        $this->aOverridesAAAA = [];

        MainLoop::GetInstance()->RegisterObject($this);
    }

    static function ParseDomainName(&$abRequest, &$dwOffset) {
        $szName = "";
        $bSetOffset = true;
        $dwCurOffset = $dwOffset;

        for(;;) {
            $bSegmentLength = ord($abRequest[$dwCurOffset]); $dwCurOffset++;
            if ($bSegmentLength == 0) {
                break;
            }
            if (($bSegmentLength & 0xc0) == 0xc0) {
                if ($bSetOffset) {
                    $dwOffset = $dwCurOffset + 1;
                    $bSetOffset = false;
                }
                $dwCurOffset = (($bSegmentLength & 0x3f) << 8) | ord($abRequest[$dwCurOffset]);
                continue;
            }
            $szName .= (strlen($szName) == 0) ? "" : ".";
            for($j = 0; $j < $bSegmentLength; $j++, $dwCurOffset++) {
                $szName .= $abRequest[$dwCurOffset];
            }
        }

        if ($bSetOffset) {
            $dwOffset = $dwCurOffset;
        }
        return $szName;
    }

    function GenerateResponse(&$abRequest, $szPeer) {
        $wQdCount = (ord($abRequest[4]) << 8) | ord($abRequest[5]);
        $dwOffset = 12;
        $wFlags = (ord($abRequest[2]) << 8) | ord($abRequest[3]);
        $wOffsetCorrect = 0;
        $wAdCount = (ord($abRequest[6]) << 8) | ord($abRequest[7]);

        $bIsAQuery = false;
        $bIsAAAAQuery = false;
        $bIsARequested = false;
        $bIsAAAARequested = false;
        $szDomainName = null;
        $dwDomainNameOffset = null;

        for ($i = 0; $i < $wQdCount; $i++) {
            $dwOffsetPreDomainName = $dwOffset;
            $szName = self::ParseDomainName($abRequest, $dwOffset);
            $wType = (ord($abRequest[$dwOffset]) << 8) | ord($abRequest[$dwOffset+1]);
            $dwOffset += 2;
            $wClass = (ord($abRequest[$dwOffset]) << 8) | ord($abRequest[$dwOffset+1]);
            $dwOffset += 2;

            if ($wType !== 1 && $wType !== 28) {
                continue;
            }

            if ($szDomainName !== null && $szName !== $szDomainName) {
                printf("[!] received single DNS query for both %s and %s from %s -- not supported\n", $szDomainName, $szName, $szPeer);
                return null;
            }
            $szDomainName = $szName;
            $dwDomainNameOffset = $dwOffsetPreDomainName;
            if ($wType === 1) {
                $bIsAQuery = true;
                if (isset($this->aOverridesA[strtolower($szName)])) {
                    $bIsARequested = true;
                }
            } else if ($wType === 28) {
                $bIsAAAAQuery = true;
                if (isset($this->aOverridesAAAA[strtolower($szName)])) {
                    $bIsAAAARequested = true;
                }
            }
        }

        if ($szDomainName === null || $wFlags & 0x8000) {
            return null;
        }

        /* determine effective addresses (specific override takes priority over catch-all) */
        $szEffectiveAddressA = null;
        $szEffectiveAddressAAAA = null;

        if ($bIsARequested) {
            $szEffectiveAddressA = $this->aOverridesA[strtolower($szDomainName)];
        } else if ($bIsAQuery && $this->szCatchAllAddress !== null) {
            $szEffectiveAddressA = $this->szCatchAllAddress;
            $bIsARequested = true;
        }

        if ($bIsAAAARequested) {
            $szEffectiveAddressAAAA = $this->aOverridesAAAA[strtolower($szDomainName)];
        }

        if (!$bIsARequested && !$bIsAAAARequested) {
            /* no overrides and no catch-all applies -> pass through to real DNS server */
            return null;
        }

        $wResponseFlags = $wFlags | 0x8080; /* 0x8000 -> is dns response, 0x80 -> recursion supported */

        $abResponse = substr($abRequest, 0, 2); /* transaction id */
        $abResponse .= chr($wResponseFlags >> 8) . chr($wResponseFlags); /* flags */
        $abResponse .= substr($abRequest, 4, 2); /* number of queries */
        $abResponse .= "\x00" . chr($bIsAAAARequested + $bIsARequested); /* number of answers */
        $abResponse .= "\x00\x00"; /* number of authority RRs */
        $abResponse .= "\x00\x00"; /* number of additional RRs */
        $abResponse .= substr($abRequest, 12, $dwOffset - 12);

        if ($bIsARequested) {
            $szOverride = $szEffectiveAddressA;
            printf("[i] applying DNS response override for %s: %s\n", $szDomainName, $szOverride);
            $dwOverride = MiscNet::Ipv4StringToDword($szOverride);
            $abOverride = chr($dwOverride >> 24) . chr($dwOverride >> 16) . chr($dwOverride >> 8) . chr($dwOverride);

            $abResponse .= "\xc0" . chr($dwDomainNameOffset); /* refer to domain name in query */
            $abResponse .= "\x00\x01"; /* type: A */
            $abResponse .= "\x00\x01"; /* class: IN */
            $abResponse .= "\x00\x00\x0e\x10"; /* TTL: 3600s */
            $abResponse .= "\x00\x04"; /* data len: 4 */
            $abResponse .= $abOverride;
        }
        if ($bIsAAAARequested) {
            $szOverride = $szEffectiveAddressAAAA;
            printf("[i] applying DNS response override for %s: %s\n", $szDomainName, $szOverride);
            $abOverride = MiscNet::Ipv6StringToBinary($szOverride);

            $abResponse .= "\xc0" . chr($dwDomainNameOffset); /* refer to domain name in query */
            $abResponse .= "\x00\x1c"; /* type: AAAA */
            $abResponse .= "\x00\x01"; /* class: IN */
            $abResponse .= "\x00\x00\x0e\x10"; /* TTL: 3600s */
            $abResponse .= "\x00\x10"; /* data len: 16 */
            $abResponse .= $abOverride;
        }

        return $abResponse;
    }

    function SetOverride($szDomainName, $szAddress) {
        if (MiscNet::Ipv4StringToDword($szAddress) !== false) {
            $this->aOverridesA[strtolower($szDomainName)] = $szAddress;
        } else if (MiscNet::Ipv6StringToBinary($szAddress) !== false) {
            $this->aOverridesAAAA[strtolower($szDomainName)] = $szAddress;
        }
    }

    function Sockets() {
        $ahSockets = [];
        if ($this->hListeningSocket != null) {
            array_push($ahSockets, $this->hListeningSocket);
        }
        if ($this->hListeningIpv6Socket != null) {
            array_push($ahSockets, $this->hListeningIpv6Socket);
        }
        if ($this->hClientSocket != null) {
            array_push($ahSockets, $this->hClientSocket);
        }
        return $ahSockets;
    }

    function BringUp() {
        if (!isset($this->szNextDns) || $this->szNextDns == null) {
            $szResolvConf = file_get_contents("/etc/resolv.conf");
            if (
                preg_match('/^nameserver\s+([0-9\.]+|[0-9a-f:]+)\s*$/im', $szResolvConf, $aMatch) && (
                    MiscNet::Ipv4StringToDword($aMatch[1]) !== false ||
                    MiscNet::Ipv6StringToBinary($aMatch[1]) !== false
                )
            ) {
                $this->szNextDns = $aMatch[1];
            } else {
                $this->Signal("dns_err", "Don't know where to forward DNS packets to");
                $this->Teardown();
                return;
            }
        }

        $dwBindAddr = ($this->dwBindAddr === null) ? 0 : $this->dwBindAddr;
        $abBindIpv6Addr = ($this->abBindIpv6Addr === null) ? str_repeat("\x00", 16) : $this->abBindIpv6Addr;
        $this->hListeningSocket = stream_socket_server("udp://" . MiscNet::DwordToIpv4String($dwBindAddr) . ":53", $dwErrno, $szErrstr, STREAM_SERVER_BIND);
        $this->hListeningIpv6Socket = stream_socket_server("udp://[" . MiscNet::BinaryToIpv6String($abBindIpv6Addr) . "]:53", $dwErrno, $szErrstr, STREAM_SERVER_BIND);
        if (MiscNet::Ipv4StringToDword($this->szNextDns) !== false) {
            $this->hClientSocket = stream_socket_client("udp://" . $this->szNextDns . ":53", $dwErrno, $szErrstr);
        } else {
            $this->hClientSocket = stream_socket_client("udp://[" . $this->szNextDns . "]:53", $dwErrno, $szErrstr);
        }

        if (
            ($this->dwBindAddr !== null && $this->hListeningSocket === false) ||
            ($this->abBindIpv6Addr !== null && $this->hListeningIpv6Socket === false) ||
            $this->hClientSocket === false
        ) {
            $this->Signal("dns_err", "Could not create DNS sockets");
            $this->Teardown();
            return;
        } else {
            $this->Signal("dns_up");
        }
    }

    function Onunblock($hSocket) {
        foreach ($this->aTransactionMap as $dwTrid => $oEntry) {
            if ($oEntry->dwExpire < intval(microtime(1) * 1000)) {
                unset($this->aTransactionMap[$dwTrid]);
            }
        }

        $abBuf = stream_socket_recvfrom($hSocket, 65536, 0, $szPeer);
        if ($abBuf === "" || $abBuf === false) {
            $this->Signal("dns_err", "DNS socket closed");
            $this->Teardown();
            return;
        }
        $wTransactionId = (ord($abBuf[0]) << 8) | ord($abBuf[1]);

        if ($hSocket === $this->hListeningSocket || $hSocket === $this->hListeningIpv6Socket) {
            $abResponse = $this->GenerateResponse($abBuf, $szPeer);
            if ($abResponse !== null) {
                stream_socket_sendto($hSocket, $abResponse, 0, $szPeer);
            } else {
                /* forward DNS query */
                $this->aTransactionMap[$wTransactionId] = new DnsTransactionMapEntry($hSocket, $szPeer, intval(microtime(1) * 1000) + 10000);
                stream_socket_sendto($this->hClientSocket, $abBuf, 0, $this->szNextDns . ":53");
            }
        } else {
            if (!isset($this->aTransactionMap[$wTransactionId])) {
                printf("[-] incoming DNS response with unknown source\n");
            } else {
                stream_socket_sendto($this->aTransactionMap[$wTransactionId]->hSocket, $abBuf, 0, $this->aTransactionMap[$wTransactionId]->szPeer);
                unset($this->aTransactionMap[$wTransactionId]);
            }
        }
    }

    function Teardown() {
        if ($this->hListeningSocket != null) {
            fclose($this->hListeningSocket);
            $this->hListeningSocket = null;
        }
        if ($this->hListeningIpv6Socket != null) {
            fclose($this->hListeningIpv6Socket);
            $this->hListeningIpv6Socket = null;
        }
        if ($this->hClientSocket != null) {
            fclose($this->hClientSocket);
            $this->hClientSocket = null;
        }
        $this->CancelAllSubscriptions();
    }
}



?>