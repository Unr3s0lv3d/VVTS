<?php

namespace VVTS\Classes;

require_once(dirname(__FILE__) . "/../autoload.php");

use \VVTS\Classes\MainLoop;
use \VVTS\Interfaces\IUnblockable;
use \VVTS\Interfaces\IScriptOpaque;
use \VVTS\Types\ScriptVoid;
use \VVTS\Types\ScriptInvokeError;
use \VVTS\Types\ScriptStringLiteral;
use \VVTS\Types\Route;
use \VVTS\Types\RouteIpv6;
use \VVTS\Types\VpnEndpointDescriptor;

$g_oMiscNet = null;

class MiscNet implements IUnblockable, IScriptOpaque {
    var $bRestoreForwardEnabled;
    var $bRestoreIpv6ForwardEnabled;
    var $szLogFile;
    var $hLogFile;

    function __construct() {
        MainLoop::GetInstance()->RegisterObject($this);
        $this->szLogFile = null;
        $this->hLogFile = null;
        $this->IptablesReset();
    }

    static function GetInstance() {
        global $g_oMiscNet;
        if ($g_oMiscNet == null) {
            $g_oMiscNet = new MiscNet();
        }
        return $g_oMiscNet;
    }

    function Sockets() {
        return [];
    }

    function Onunblock($hSocket) { }

    function Teardown() {
        if ($this->bRestoreForwardEnabled !== null) {
            @file_put_contents("/proc/sys/net/ipv4/ip_forward", intval($this->bRestoreForwardEnabled));
            $this->bRestoreForwardEnabled = null;
        }
        if ($this->bRestoreIpv6ForwardEnabled !== null) {
            @file_put_contents("/proc/sys/net/ipv6/conf/all/forwarding", intval($this->bRestoreIpv6ForwardEnabled));
            $this->bRestoreIpv6ForwardEnabled = null;
        }

        $this->IptablesReset();

        if ($this->hLogFile !== null) {
            fwrite($this->hLogFile, "[" . date('Y-m-d H:i:s') . "] === VVTS sessie gestopt ===\n");
            fflush($this->hLogFile);
            ob_end_flush();
            fclose($this->hLogFile);
            $this->hLogFile = null;
            $this->szLogFile = null;
        }
    }

    function IptablesReset() {
        MiscNet::IptablesDeinitBranch(false, "nat", "POSTROUTING", "VVTS_POSTROUTING_MASQ");
        MiscNet::IptablesDeinitBranch(false, "nat", "PREROUTING", "VVTS_PREROUTING_REDIRECT");
        MiscNet::IptablesDeinitBranch(false, "filter", "FORWARD", "VVTS_FORWARD_DEFAULT");
        MiscNet::IptablesDeinitBranch(true, "nat", "POSTROUTING", "VVTS_POSTROUTING_MASQ");
        MiscNet::IptablesDeinitBranch(true, "nat", "PREROUTING", "VVTS_PREROUTING_REDIRECT");
        MiscNet::IptablesDeinitBranch(true, "filter", "FORWARD", "VVTS_FORWARD_DEFAULT");
    }

    static function Ipv4StringToDword($szAddr) {
        if (is_string($szAddr) && preg_match('/^(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[0-9]{0,2})\.(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[0-9]{0,2})\.(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[0-9]{0,2})\.(25[0-5]|2[0-4][0-9]|[0-1][0-9]{2}|[0-9]{0,2})$/', $szAddr, $aMatchIp)) {
            return (intval($aMatchIp[1]) << 24) | (intval($aMatchIp[2]) << 16) | (intval($aMatchIp[3]) << 8) | intval($aMatchIp[4]);
        }

        return false;
    }

    static function DwordToIpv4String($dwAddr) {
        return (($dwAddr >> 24) & 0xff) . "." . (($dwAddr >> 16) & 0xff) . "." . (($dwAddr >> 8) & 0xff) . "." . ($dwAddr & 0xff);
    }

    static function Ipv6StringToBinary($szAddr) {
        $aszGroups = [];
        $szCurGroup = "";
        $bHitExpand = false;

        for ($i = 0; $i <= strlen($szAddr); $i++) {
            if (
                $i < strlen($szAddr) &&
                count($aszGroups) != 0 &&
                strlen($szCurGroup) == 0 &&
                ($dwIpv4Addr = self::Ipv4StringToDword(substr($szAddr, $i))) !== false
            ) {
                /* input string ends with IPv4 notation */
                array_push($aszGroups, sprintf("%x%02x", ($dwIpv4Addr >> 24) & 0xff, ($dwIpv4Addr >> 16) & 0xff));
                array_push($aszGroups, sprintf("%x%02x", ($dwIpv4Addr >> 8) & 0xff, $dwIpv4Addr & 0xff));
                $i = strlen($szAddr) - 1;
            } else if (
                ($i < strlen($szAddr) && ord($szAddr[$i]) >= ord('0') && ord($szAddr[$i]) <= ord('9')) ||
                ($i < strlen($szAddr) && (ord($szAddr[$i]) | 0x20) >= ord('a') && (ord($szAddr[$i]) | 0x20) <= ord('f'))
            ) {
                /* normal hex char */
                $szCurGroup .= $szAddr[$i];
            } else if ($i == strlen($szAddr) || $szAddr[$i] === ':') {
                /* end of group or end of string */
                if ($i+1 < strlen($szAddr) && $szAddr[$i+1] === ':') {
                    /* encountered '::' for expansion */
                    if ($bHitExpand) {
                        return false;
                    }
                    $bHitExpand = true;
                    if (strlen($szCurGroup) == 0 && $i != 0) {
                        /* encountered ':::' */
                        return false;
                    } else if (strlen($szCurGroup) > 4) {
                        /* encountered 5 or more hex chars */
                        return false;
                    } else if (strlen($szCurGroup) != 0) {
                        /* add preceding group to array */
                        array_push($aszGroups, $szCurGroup);
                        $szCurGroup = "";
                    }
                    /* empty string indicates expansion */
                    array_push($aszGroups, "");
                    $i++;
                } else {
                    if (($i != strlen($szAddr) && strlen($szCurGroup) == 0) || strlen($szCurGroup) > 4) {
                        /* invalid size of group */
                        return false;
                    } else if (strlen($szCurGroup) != 0) {
                        /* end of group -> add to list */
                        array_push($aszGroups, $szCurGroup);
                    }
                    $szCurGroup = "";
                }
            } else if ($i < strlen($szAddr)) {
                /* invalid character */
                return false;
            }
        }

        if (count($aszGroups) > 8) {
            return false;
        }

        $abBinary = "";
        foreach($aszGroups as $i => $szGroup) {
            if (strlen($szGroup) == 0) {
                /* expansion (count to 9, not 8, because it includes an empty string) */
                for ($j = 0; $j < (9 - count($aszGroups)); $j++) {
                    $abBinary .= "\x00\x00";
                }
            } else {
                /* normal group, convert to binary */
                $wGroup = hexdec($szGroup);
                $abBinary .= chr($wGroup >> 8) . chr($wGroup);
            }
        }
        return $abBinary;
    }

    static function BinaryToIpv6String($abBinary) {
        if (strlen($abBinary) != 16) {
            return false;
        }

        $szAddrStr = "";
        $aGap = null;
        $dwGapStart = -1;

        for($i = 0; $i < strlen($abBinary); $i+=2) {
            $wGroup = (ord($abBinary[$i]) << 8) | ord($abBinary[$i+1]);
            if ($wGroup === 0 && $dwGapStart === -1) {
                $dwGapStart = $i;
            } else if ($wGroup !== 0 && $dwGapStart !== -1) {
                if ($aGap === null || ($aGap[1] - $aGap[0]) < ($i - $dwGapStart)) {
                    $aGap = [$dwGapStart, $i];
                }
                $dwGapStart = -1;
            }
            if ($dwGapStart !== -1 && $i === 14) {
                if ($aGap === null || ($aGap[1] - $aGap[0]) < ($i+2-$dwGapStart)) {
                    $aGap = [$dwGapStart, $i+2];
                }
            }
        }

        for($i = 0; $i < strlen($abBinary); $i+=2) {
            if ($aGap != null && $aGap[0] === $i) {
                $szAddrStr .= (strlen($szAddrStr) == 0) ? "::" : ":";
                $i = $aGap[1]-2;
                continue;
            }
            $wGroup = (ord($abBinary[$i]) << 8) | ord($abBinary[$i+1]);
            $szAddrStr .= dechex($wGroup);
            if ($i != 14) {
                $szAddrStr .= ":";
            }
        }

        return $szAddrStr;
    }

    static function Ipv4ToNat64($dwIpv4Addr) {
        if (!is_int($dwIpv4Addr)) {
            return false;
        }
        return "\x00\x64\xff\x9b\x00\x00\x00\x00\x00\x00\x00\x00" . chr($dwIpv4Addr >> 24) . chr($dwIpv4Addr >> 16) . chr($dwIpv4Addr >> 8) . chr($dwIpv4Addr);
    }

    static function NetmaskToPrefixLength($dwNetmask) {
        for ($bOn = 0, $i = 0; $i < 32; $i++) {
            if (!($dwNetmask & (1 << (31 - $i)))) {
                break;
            }
        }

        return $i;
    }

    function StateMachineInvoke_subnet_ip(...$aArguments) {
        if (count($aArguments) != 2) {
            throw new ScriptInvokeError("subnet_ip requires an ip address and a netmask");
        } else if (!($aArguments[0] instanceof ScriptStringLiteral) || !($aArguments[1] instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("subnet_ip requires both parameters to be a string");
        }
        $oIpAddr = $aArguments[0];
        $oNetmask = $aArguments[1];

        $dwIpAddr = self::Ipv4StringToDword($oIpAddr->szLiteral);
        $dwNetmask = self::Ipv4StringToDword($oNetmask->szLiteral);

        if ($dwIpAddr === false || $dwNetmask === false) {
            throw new ScriptInvokeError("Invalid IPv4 address: " . ($dwIpAddr === false ? $oIpAddr->szLiteral : $oNetmask->szLiteral));
        }

        for($bOn = 0, $i = 0; $i < 32; $i++) {
            if ($dwNetmask & (1 << $i)) {
                if (!$bOn) { $bOn = 1; }
            } else {
                if ($bOn) { throw new ScriptInvokeError("Invalid IPv4 netmask"); }
            }
        }

        $dwReturnValue = $dwIpAddr & $dwNetmask;
        $dwReturnValue++;
        if ($dwReturnValue == $dwIpAddr) {
            $dwReturnValue++;
        }

        return new ScriptStringLiteral(self::DwordToIpv4String($dwReturnValue));
    }

    function StateMachineInvoke_subnet_ipv6(...$aArguments) {
        if (count($aArguments) != 2) {
            throw new ScriptInvokeError("subnet_ipv6 requires an ip address and a prefix length");
        } else if (!($aArguments[0] instanceof ScriptStringLiteral) || !($aArguments[1] instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("subnet_ipv6 requires both parameters to be a string");
        }
        $oIpv6Addr = $aArguments[0];
        $oPrefixLen = $aArguments[1];

        $abIpv6Addr = self::Ipv6StringToBinary($oIpv6Addr->szLiteral);
        $dwPrefixLen = intval($oPrefixLen->szLiteral);

        if ($abIpv6Addr === false) {
            throw new ScriptInvokeError("Invalid IPv6 address: " . $oIpv6Addr->szLiteral);
        } else if ($dwPrefixLen < 0 || $dwPrefixLen > 128) {
            throw new ScriptInvokeError("Invalid prefix length: " . $oPrefixLen->szLiteral);
        }

        /* apply netmask to ipv6 address */
        $abReturnAddr = "";
        for ($i = 0; $i < 16; $i++) {
            if ($i < ($dwPrefixLen >> 3)) {
                $abReturnAddr .= $abIpv6Addr[$i];
            } else if ($i == ($dwPrefixLen >> 3)) {
                $abReturnAddr .= chr(ord($abIpv6Addr[$i]) & (0xff00 >> ($dwPrefixLen & 7)));
            } else {
                $abReturnAddr .= "\x00";
            }
        }

        /* if it equals the input address -> increment by one */
        if ($abReturnAddr === $abIpv6Addr) {
            for ($i = 15; $i >= 0; $i--) {
                $bVal = ord($abReturnAddr[$i]) + 1;
                $abReturnAddr[$i] = chr($bVal);
                if ($bVal === 256) {
                    /* carry */
                    continue;
                }
                break;
            }
        }

        return new ScriptStringLiteral(self::BinaryToIpv6String($abReturnAddr));
    }

    function StateMachineInvoke_lookup_ipv4(...$aArguments) {
        if (count($aArguments) != 1) {
            throw new ScriptInvokeError("lookup_ipv4 requires an argument");
        } else if (!($aArguments[0] instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("lookup_ipv4 requires a string as input parameter");
        }
        $oHostname = $aArguments[0];
        $aLookupResult = dns_get_record($oHostname->szLiteral, DNS_A);
        if (is_array($aLookupResult) && isset($aLookupResult[0]["ip"])) {
            return new ScriptStringLiteral($aLookupResult[0]["ip"]);
        } else {
            return new ScriptStringLiteral("");
        }
    }

    function StateMachineInvoke_lookup_ipv6(...$aArguments) {
        if (count($aArguments) != 1) {
            throw new ScriptInvokeError("lookup_ipv6 requires an argument");
        } else if (!($aArguments[0] instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("lookup_ipv6 requires a string as input parameter");
        }
        $oHostname = $aArguments[0];
        $aLookupResult = dns_get_record($oHostname->szLiteral, DNS_AAAA);
        if (is_array($aLookupResult) && isset($aLookupResult[0]["ipv6"])) {
            return new ScriptStringLiteral($aLookupResult[0]["ipv6"]);
        } else {
            return new ScriptStringLiteral("");
        }
    }

    static function GetRouteTable() {
        $szShellExecOutput = shell_exec("ip route list");
        $szShellDefaultRoute = preg_replace("/\s+/", " ", shell_exec("ip route get 0.0.0.1"));
        $szShellExecOutput = "dflget " . $szShellDefaultRoute . "\n" . $szShellExecOutput;

        $aszShellExecOutput = preg_split("/\r?\n/s", $szShellExecOutput);
        $aOutput = [];

        foreach($aszShellExecOutput as $szLine) {
            if (!preg_match('/^(default|dflget|[0-9\.]+(?:\/[0-9]+)?)/m', $szLine, $aMatchSubnet)) {
                continue;
            }

            if ($aMatchSubnet[1] === "default") {
                // $dwSubnet = 0;
                // $dwNetmask = 0;
                // handled in dflget
                continue;
            } else if ($aMatchSubnet[1] === "dflget") {
                $dwSubnet = 0;
                $dwNetmask = 0;
            } else {
                if (strpos($aMatchSubnet[1], '/') !== false) {
                    list ($szSubnet, $szNetmaskBits) = explode('/', $aMatchSubnet[1], 2);
                    $dwSubnet = MiscNet::Ipv4StringToDword($szSubnet);
                    $dwNetmask = ~((1 << (32 - intval($szNetmaskBits))) - 1) & 0xffffffff;
                } else {
                    $dwSubnet = MiscNet::Ipv4StringToDword($aMatchSubnet[1]);
                    $dwNetmask = 0xffffffff;
                }
            }

            $szDev = null;
            if (preg_match('/dev ([^\s]+)/', $szLine, $aMatchDev)) {
                $szDev = $aMatchDev[1];
            } else {
                continue;
            }
            $dwVia = null;
            if (preg_match('/via ([0-9\.]+)/', $szLine, $aMatchVia)) {
                $dwVia = MiscNet::Ipv4StringToDword($aMatchVia[1]);
            }
            $dwSrc = null;
            if (preg_match('/src ([0-9\.]+)/', $szLine, $aMatchSrc)) {
                $dwSrc = MiscNet::Ipv4StringToDword($aMatchSrc[1]);
            }

            $oRoute = new Route($dwSubnet, $dwNetmask, $dwVia, $szDev, $dwSrc);
            array_push($aOutput, $oRoute);
        }

        return $aOutput;
    }

    static function GetDefaultRoute() {
        $aRouteTable = MiscNet::GetRouteTable();

        foreach($aRouteTable as $oRoute) {
            if ($oRoute->dwSubnet === 0 && $oRoute->dwNetmask === 0) {
                return $oRoute;
            }
        }

        return null;
    }

    static function GetRouteTableIpv6() {
        $szShellExecOutput = shell_exec("ip -6 route list");
        $szShellDefaultRoute = preg_replace("/\s+/", " ", shell_exec("ip -6 route get ::"));
        $szShellExecOutput = "dflget " . $szShellDefaultRoute . "\n" . $szShellExecOutput;

        $aszShellExecOutput = preg_split("/\r?\n/s", $szShellExecOutput);
        $aOutput = [];

        foreach($aszShellExecOutput as $szLine) {
            if (!preg_match('/^(default|dflget|[0-9a-f:]+(?:\/[0-9]+)?)/m', $szLine, $aMatchSubnet)) {
                continue;
            }

            if ($aMatchSubnet[1] === "default") {
                // $abSubnet = str_repeat("\x00", 16);
                // $dwPrefixLen = 0;
                // handled in dflget
                continue;
            } else if ($aMatchSubnet[1] === "dflget") {
                $abSubnet = str_repeat("\x00", 16);
                $dwPrefixLen = 0;
            } else {
                if (strpos($aMatchSubnet[1], '/') !== false) {
                    list ($szSubnet, $szPrefixLen) = explode('/', $aMatchSubnet[1], 2);
                    $abSubnet = MiscNet::Ipv6StringToBinary($szSubnet);
                    $dwPrefixLen = intval($szPrefixLen);
                } else {
                    $abSubnet = MiscNet::Ipv6StringToBinary($aMatchSubnet[1]);
                    $dwPrefixLen = 128;
                }
            }

            $szDev = null;
            if (preg_match('/dev ([^\s]+)/', $szLine, $aMatchDev)) {
                $szDev = $aMatchDev[1];
            } else {
                continue;
            }
            $abVia = null;
            if (preg_match('/via ([0-9a-f:]+)/', $szLine, $aMatchVia)) {
                $abVia = MiscNet::Ipv6StringToBinary($aMatchVia[1]);
            }
            $abSrc = null;
            if (preg_match('/src ([0-9a-f:]+)/', $szLine, $aMatchSrc)) {
                $abSrc = MiscNet::Ipv6StringToBinary($aMatchSrc[1]);
            }

            $oRoute = new RouteIpv6($abSubnet, $dwPrefixLen, $abVia, $szDev, $abSrc);
            array_push($aOutput, $oRoute);
        }

        return $aOutput;
    }

    static function GetDefaultRouteIpv6() {
        $aRouteTable = MiscNet::GetRouteTableIpv6();

        foreach($aRouteTable as $oRoute) {
            if ($oRoute->abSubnet === str_repeat("\x00", 16) && $oRoute->dwPrefixLen === 0) {
                return $oRoute;
            }
        }

        return null;
    }

    static function AddRoute($dwAddr, $dwNetmask, $dwVia, $szDev) {
        shell_exec(
            "ip route" .
                " add " . escapeshellarg(MiscNet::DwordToIpv4String($dwAddr)) . ($dwNetmask === false ? "" : "/" . escapeshellarg(MiscNet::NetmaskToPrefixLength($dwNetmask))) .
                (($dwVia === false) ? "" : " via " . escapeshellarg(MiscNet::DwordToIpv4String($dwVia))) .
                " dev " . escapeshellarg($szDev) .
                " 2>/dev/null"
        );
    }

    static function AddRouteIpv6($abAddr, $dwPrefixLen, $abVia, $szDev) {
        shell_exec(
            "ip -6 route" .
                " add " . escapeshellarg(MiscNet::BinaryToIpv6String($abAddr)) . ($dwPrefixLen === false ? "" : "/" . intval($dwPrefixLen)) .
                (($abVia === false) ? "" : " via " . escapeshellarg(MiscNet::BinaryToIpv6String($abVia))) .
                " dev " . escapeshellarg($szDev) .
                " 2>/dev/null"
        );
    }

    static function DelRoute($dwAddr, $dwNetmask) {
        shell_exec(
            "ip route" .
                " del " . escapeshellarg(MiscNet::DwordToIpv4String($dwAddr)) .
                    ($dwNetmask === false ? "" : "/" . escapeshellarg(MiscNet::NetmaskToPrefixLength($dwNetmask))) .
                " 2>/dev/null"
        );
    }

    static function DelRouteIpv6($abAddr, $dwPrefixLen) {
        shell_exec(
            "ip -6 route" .
                " del " . escapeshellarg(MiscNet::BinaryToIpv6String($abAddr)) .
                    ($dwPrefixLen === false ? "" : "/" . intval($dwPrefixLen)) .
                " 2>/dev/null"
        );
    }

    static function IptablesInitBranch($bIsIpv6, $szTable, $szChain, $szNewChain, $bFlushIfExists=true) {
        $szErrmsg = shell_exec("ip" . ($bIsIpv6 ? "6" : "") . "tables -t " . escapeshellarg($szTable) . " -N " . escapeshellarg($szNewChain) . " 2>&1");
        if (strpos($szErrmsg, "already exists")) {
            if ($bFlushIfExists) {
                shell_exec("ip" . ($bIsIpv6 ? "6" : "") . "tables -t " . escapeshellarg($szTable) . " -F " . escapeshellarg($szNewChain));
            }
        } else {
            shell_exec("ip" . ($bIsIpv6 ? "6" : "") . "tables -t " . escapeshellarg($szTable) . " -A " . escapeshellarg($szChain) . " -j " . escapeshellarg($szNewChain));
        }
    }
    static function IptablesDeinitBranch($bIsIpv6, $szTable, $szChain, $szNewChain) {
        shell_exec("ip" . ($bIsIpv6 ? "6" : "") . "tables -t " . escapeshellarg($szTable) . " -D " . escapeshellarg($szChain) . " -j " . escapeshellarg($szNewChain) . " 2>/dev/null");
        shell_exec("ip" . ($bIsIpv6 ? "6" : "") . "tables -t " . escapeshellarg($szTable) . " -F " . escapeshellarg($szNewChain) . " 2>/dev/null");
        shell_exec("ip" . ($bIsIpv6 ? "6" : "") . "tables -t " . escapeshellarg($szTable) . " -X " . escapeshellarg($szNewChain) . " 2>/dev/null");
    }

    function StateMachineSet_log_file($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("log_file must be of type string");
        }

        /* leeg pad = logging uitschakelen */
        if ($oValue->szLiteral === "") {
            if ($this->hLogFile !== null) {
                printf("[i] logging uitgeschakeld\n");
                fwrite($this->hLogFile, "[" . date('Y-m-d H:i:s') . "] === logging uitgeschakeld ===\n");
                fflush($this->hLogFile);
                ob_end_flush();
                fclose($this->hLogFile);
                $this->hLogFile = null;
                $this->szLogFile = null;
            }
            return;
        }

        /* al actieve logging netjes afsluiten voor we een nieuwe openen */
        if ($this->hLogFile !== null) {
            fwrite($this->hLogFile, "[" . date('Y-m-d H:i:s') . "] === logging omgeleid naar " . $oValue->szLiteral . " ===\n");
            fflush($this->hLogFile);
            ob_end_flush();
            fclose($this->hLogFile);
            $this->hLogFile = null;
        }

        $szLogFile = $oValue->szLiteral;
        $szDir = dirname($szLogFile);

        if (!is_dir($szDir)) {
            throw new ScriptInvokeError("log_file: map bestaat niet: " . $szDir);
        }

        $hLogFile = fopen($szLogFile, 'a');
        if ($hLogFile === false) {
            throw new ScriptInvokeError("log_file: kan bestand niet openen voor schrijven: " . $szLogFile);
        }

        $this->szLogFile = $szLogFile;
        $this->hLogFile = $hLogFile;

        /* sessie-markering in het logbestand */
        fwrite($hLogFile, "\n[" . date('Y-m-d H:i:s') . "] === VVTS sessie gestart ===\n");
        fflush($hLogFile);

        /*
         * Zet output buffering op als tee: elke printf() wordt naar zowel de
         * terminal als het logbestand gestuurd. chunk_size=1 zorgt dat output
         * real-time wordt doorgesluisd (geen vertraging in de main loop).
         */
        ob_start(function($buffer) use ($hLogFile) {
            fwrite($hLogFile, $buffer);
            fflush($hLogFile);
            return $buffer; /* ook op de terminal tonen */
        }, 1);
        ob_implicit_flush(true);

        printf("[i] logging naar %s\n", $szLogFile);
    }

    function StateMachineInvoke_masquerade(...$aArguments) {
        if (count($aArguments) != 1) {
            throw new ScriptInvokeError("masquerade requires an argument");
        } else if (!($aArguments[0] instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("masquerade requires a string as input parameter");
        }
        $oValue = $aArguments[0];
        $bValue = trim(strtolower($oValue->szLiteral)) === "true" || intval(trim($oValue->szLiteral)) !== 0;
        $bForwardEnabled = intval(@file_get_contents("/proc/sys/net/ipv4/ip_forward"));
        $bIpv6ForwardEnabled = intval(@file_get_contents("/proc/sys/net/ipv6/conf/all/forwarding"));
        $oDefaultRoute = MiscNet::GetDefaultRoute();
        $oDefaultRouteIpv6 = MiscNet::GetDefaultRouteIpv6();

        if ($bValue) {
            MiscNet::IptablesInitBranch(false, "nat", "POSTROUTING", "VVTS_POSTROUTING_MASQ");
            MiscNet::IptablesInitBranch(false, "filter", "FORWARD", "VVTS_FORWARD_DEFAULT");
            if ($oDefaultRoute !== null) {
                shell_exec("iptables -t nat -A VVTS_POSTROUTING_MASQ -o " . escapeshellarg($oDefaultRoute->szDev) . " -j MASQUERADE");

                if (!$bForwardEnabled) {
                    if ($this->bRestoreForwardEnabled === null) {
                        $this->bRestoreForwardEnabled = 0;
                    }
                    @file_put_contents("/proc/sys/net/ipv4/ip_forward", "1");
                }

                shell_exec("iptables -A VVTS_FORWARD_DEFAULT -o " . escapeshellarg($oDefaultRoute->szDev) . " -j ACCEPT");
                shell_exec("iptables -A VVTS_FORWARD_DEFAULT -i " . escapeshellarg($oDefaultRoute->szDev) . " -j ACCEPT");
            }

            MiscNet::IptablesInitBranch(true, "nat", "POSTROUTING", "VVTS_POSTROUTING_MASQ");
            MiscNet::IptablesInitBranch(true, "filter", "FORWARD", "VVTS_FORWARD_DEFAULT");
            if ($oDefaultRouteIpv6 !== null) {
                shell_exec("ip6tables -t nat -A VVTS_POSTROUTING_MASQ -o " . escapeshellarg($oDefaultRouteIpv6->szDev) . " -j MASQUERADE");

                if(!$bIpv6ForwardEnabled) {
                    if ($this->bRestoreIpv6ForwardEnabled === null) {
                        $this->bRestoreIpv6ForwardEnabled = 0;
                    }
                    @file_put_contents("/proc/sys/net/ipv6/conf/all/forwarding", "1");
                }

                shell_exec("ip6tables -A VVTS_FORWARD_DEFAULT -o " . escapeshellarg($oDefaultRouteIpv6->szDev) . " -j ACCEPT");
                shell_exec("ip6tables -A VVTS_FORWARD_DEFAULT -i " . escapeshellarg($oDefaultRouteIpv6->szDev) . " -j ACCEPT");
            }
        } else {
            MiscNet::IptablesDeinitBranch(false, "nat", "POSTROUTING", "VVTS_POSTROUTING_MASQ");
            MiscNet::IptablesDeinitBranch(false, "filter", "FORWARD", "VVTS_FORWARD_DEFAULT");
            MiscNet::IptablesDeinitBranch(true, "nat", "POSTROUTING", "VVTS_POSTROUTING_MASQ");
            MiscNet::IptablesDeinitBranch(true, "filter", "FORWARD", "VVTS_FORWARD_DEFAULT");
        }

        return new ScriptVoid();
    }

    function StateMachineInvoke_no_redirect(...$aArguments) {
        if (count($aArguments) != 1) {
            throw new ScriptInvokeError("no_redirect requires an argument");
        } else if (!($aArguments[0] instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("no_redirect requires parameter to be a string");
        }
        $oNoRedirect = $aArguments[0];
        $oDesc = VpnEndpointDescriptor::FromString($oNoRedirect->szLiteral);

        if ($oDesc === null) {
            $oDesc = new VpnEndpointDescriptor(null, $oNoRedirect->szLiteral, null);
        }

        $bIpv4AddrExists = false;
        $bIpv6AddrExists = false;
        if (MiscNet::Ipv4StringToDword($oDesc->szHostname) !== false) {
            $aHosts = [["type" => "A", "ip" => $oDesc->szHostname]];
            $bIpv4AddrExists = true;
            $bIpv6AddrExists = true;
        } else if (MiscNet::Ipv6StringToBinary($oDesc->szHostname) !== false) {
            $aHosts = [["type" => "AAAA", "ipv6" => $oDesc->szHostname]];
            $bIpv6AddrExists = true;
        } else if (!is_array(($aHosts = dns_get_record($oDesc->szHostname, DNS_A | DNS_AAAA))) || count($aHosts) == 0) {
            throw new ScriptInvokeError("could not resolve address " . $oDesc->szHostname);
        } else {
            foreach($aHosts as $i => $oDnsResult) {
                if ($oDnsResult["type"] === "A") {
                    $bIpv4AddrExists = true;
                    $bIpv6AddrExists = true;
                } else if ($oDnsResult["type"] === "AAAA") {
                    $bIpv6AddrExists = true;
                }
            }
        }

        if ($bIpv4AddrExists) {
            MiscNet::IptablesInitBranch(false, "nat", "PREROUTING", "VVTS_PREROUTING_REDIRECT", false);
            foreach($aHosts as $oLookupResult) {
                if ($oLookupResult["type"] !== "A") {
                    continue;
                }

                shell_exec(
                    "iptables -t nat -I VVTS_PREROUTING_REDIRECT 1" .
                    (($oDesc->bProtocol === null) ? "" : " -p " . intval($oDesc->bProtocol)) .
                    " -d " . escapeshellarg($oLookupResult["ip"]) .
                    (($oDesc->wPort === null) ? "" : " --dport " . intval($oDesc->wPort)) .
                    " -j RETURN 2>/dev/null"
                );
            }
        }
        if ($bIpv6AddrExists) {
            MiscNet::IptablesInitBranch(true, "nat", "PREROUTING", "VVTS_PREROUTING_REDIRECT", false);
            foreach($aHosts as $oLookupResult) {
                if ($oLookupResult["type"] !== "AAAA" && $oLookupResult["type"] !== "A") {
                    continue;
                }

                if ($oLookupResult["type"] === "A") {
                    $oLookupResult["ipv6"] = MiscNet::BinaryToIPv6String(MiscNet::Ipv4ToNat64(MiscNet::Ipv4StringToDword($oLookupResult["ip"])));
                }

                shell_exec(
                    "ip6tables -t nat -I VVTS_PREROUTING_REDIRECT 1" .
                    (($oDesc->bProtocol === null) ? "" : " -p " . intval($oDesc->bProtocol)) .
                    " -d " . escapeshellarg($oLookupResult["ipv6"]) .
                    (($oDesc->wPort === null) ? "" : " --dport " . intval($oDesc->wPort)) .
                    " -j RETURN 2>/dev/null"
                );
            }
        }

        return new ScriptVoid();
    }

    function StateMachineInvoke_set_redirect(...$aArguments) {
        if (count($aArguments) != 2) {
            throw new ScriptInvokeError("set_redirect requires two arguments");
        } else if (!($aArguments[0] instanceof ScriptStringLiteral) || !($aArguments[1] instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("set_redirect requires both parameters to be a string");
        }
        $oRedirectFrom = $aArguments[0];
        $oRedirectTo = $aArguments[1];

        $oDescFrom = VpnEndpointDescriptor::FromString($oRedirectFrom->szLiteral);
        $oDescTo = VpnEndpointDescriptor::FromString($oRedirectTo->szLiteral);

        if ($oDescFrom === null) {
            /* create wildcard VpnEndpointDescriptor matching any protocol or port */
            $oDescFrom = new VpnEndpointDescriptor(null, $oRedirectFrom->szLiteral, null);
        }
        if ($oDescTo === null) {
            /* create wildcard VpnEndpointDescriptor matching any protocol or port */
            $oDescTo = new VpnEndpointDescriptor(null, $oRedirectTo->szLiteral, null);
        }

        if ($oDescFrom->bProtocol !== $oDescTo->bProtocol) {
            throw new ScriptInvokeError("protocols for source and destination must match");
        }

        $bIpv4SourceExists = false;
        $bIpv6SourceExists = false;
        if (MiscNet::Ipv4StringToDword($oDescFrom->szHostname) !== false) {
            $aHostsFrom = [["type" => "A", "ip" => $oDescFrom->szHostname]];
            $bIpv4SourceExists = true;
            $bIpv6SourceExists = true;
        } else if (MiscNet::Ipv6StringToBinary($oDescFrom->szHostname) !== false) {
            $aHostsFrom = [["type" => "AAAA", "ipv6" => $oDescFrom->szHostname]];
            $bIpv6SourceExists = true;
        } else if (!is_array(($aHostsFrom = dns_get_record($oDescFrom->szHostname, DNS_A | DNS_AAAA))) || count($aHostsFrom) == 0) {
            throw new ScriptInvokeError("could not resolve address " . $oDescFrom->szHostname);
        } else {
            foreach($aHostsFrom as $i => $oDnsResult) {
                if ($oDnsResult["type"] === "A") {
                    $bIpv4SourceExists = true;
                    $bIpv6SourceExists = true;
                } else if ($oDnsResult["type"] === "AAAA") {
                    $bIpv6SourceExists = true;
                }
            }
        }

        $szIpv4Target = null;
        $szIpv6Target = null;
        if (MiscNet::Ipv4StringToDword($oDescTo->szHostname) !== false) {
            $aHostsTo = [["type" => "A", "ip" => $oDescTo->szHostname]];
            $szIpv4Target = $oDescTo->szHostname;
        } else if (MiscNet::Ipv6StringToBinary($oDescTo->szHostname) !== false) {
            $aHostsTo = [["type" => "AAAA", "ipv6" => $oDescTo->szHostname]];
            $szIpv6Target = $oDescTo->szHostname;
        } else if (!is_array(($aHostsTo = dns_get_record($oDescTo->szHostname, DNS_A | DNS_AAAA))) || count($aHostsTo) == 0) {
            throw new ScriptInvokeError("could not resolve address " . $oDescTo->szHostname);
        } else {
            foreach($aHostsTo as $i => $oDnsResult) {
                if ($oDnsResult["type"] === "A") {
                    if ($szIpv4Target === NULL) {
                        $szIpv4Target = $oDnsResult["ip"];
                    }
                } else if ($oDnsResult["type"] === "AAAA") {
                    if ($szIpv6Target === NULL) {
                        $szIpv6Target = $oDnsResult["ipv6"];
                    }
                }
            }
        }

        if ($szIpv6Target === null && $szIpv4Target !== null) {
            $szIpv6Target = MiscNet::BinaryToIPv6String(MiscNet::Ipv4ToNat64(MiscNet::Ipv4StringToDword($szIpv4Target)));
        }

        if (!(
            ($bIpv4SourceExists && $szIpv4Target !== null) ||
            ($bIpv6SourceExists && $szIpv6Target !== null)
        )) {
            throw new ScriptInvokeError("cannot cross-redirect ipv4 and ipv6 traffic");
        }

        if ($bIpv4SourceExists && $szIpv4Target !== null) {
            MiscNet::IptablesInitBranch(false, "nat", "PREROUTING", "VVTS_PREROUTING_REDIRECT", false);
            foreach($aHostsFrom as $oLookupResultFrom) {
                if ($oLookupResultFrom["type"] !== "A") {
                    continue;
                }

                shell_exec(
                    "iptables -t nat -A VVTS_PREROUTING_REDIRECT" .
                    (($oDescFrom->bProtocol === null) ? "" : " -p " . intval($oDescFrom->bProtocol)) .
                    " -d " . escapeshellarg($oLookupResultFrom["ip"]) .
                    (($oDescFrom->wPort === null) ? "" : " --dport " . intval($oDescFrom->wPort)) .
                    " -j DNAT --to " . escapeshellarg($szIpv4Target) .
                    (($oDescTo->wPort === null) ? "" : ":" . intval($oDescTo->wPort))
                );
            }
        }

        if ($bIpv6SourceExists && $szIpv6Target !== null) {
            MiscNet::IptablesInitBranch(true, "nat", "PREROUTING", "VVTS_PREROUTING_REDIRECT", false);
            foreach($aHostsFrom as $oLookupResultFrom) {
                if ($oLookupResultFrom["type"] !== "AAAA" && $oLookupResultFrom["type"] !== "A") {
                    continue;
                }

                if ($oLookupResultFrom["type"] === "A") {
                    $oLookupResultFrom["ipv6"] = MiscNet::BinaryToIPv6String(MiscNet::Ipv4ToNat64(MiscNet::Ipv4StringToDword($oLookupResultFrom["ip"])));
                }

                shell_exec(
                    "ip6tables -t nat -A VVTS_PREROUTING_REDIRECT" .
                    (($oDescFrom->bProtocol === null) ? "" : " -p " . intval($oDescFrom->bProtocol)) .
                    " -d " . escapeshellarg($oLookupResultFrom["ipv6"]) .
                    (($oDescFrom->wPort === null) ? "" : " --dport " . intval($oDescFrom->wPort)) .
                    " -j DNAT --to " . escapeshellarg($szIpv6Target) .
                    (($oDescTo->wPort === null) ? "" : ":" . intval($oDescTo->wPort))
                );
            }
        }

        return new ScriptVoid();
    }
}

?>