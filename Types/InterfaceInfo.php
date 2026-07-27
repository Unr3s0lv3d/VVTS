<?php

namespace VVTS\Types;

require_once(dirname(__FILE__) . "/../autoload.php");

use \VVTS\Classes\MiscNet;

class InterfaceInfo {
    var $dwIpAddr;
    var $dwNetmask;
    var $abIpv6Addr;
    var $dwIpv6PrefixLen;
    var $abMacAddress;

    function __construct($dwIpAddr, $dwNetmask, $abIpv6Addr, $dwIpv6PrefixLen, $abMacAddress) {
        $this->dwIpAddr = $dwIpAddr;
        $this->dwNetmask = $dwNetmask;
        $this->abIpv6Addr = $abIpv6Addr;
        $this->dwIpv6PrefixLen = $dwIpv6PrefixLen;
        $this->abMacAddress = $abMacAddress;
    }

    static function FromInterface($szInterface) {
        $szConfig = shell_exec("ifconfig " . escapeshellarg($szInterface) . " 2>&1");
        if (preg_match('/\sflags=([0-9]+)/', $szConfig, $aMatchFlags)) {
            $dwFlags = $aMatchFlags[1];
        } else {
            return null;
        }
        $szIpAddr = "0.0.0.0";
        $szNetmask = null;
        if (preg_match('/inet\s+([0-9\.]+)\s+netmask\s+([0-9\.]+)/', $szConfig, $aMatchSubnet)) {
            $szIpAddr = $aMatchSubnet[1];
            $szNetmask = $aMatchSubnet[2];
        }
        $abIpv6Addr = false;
        $dwIpv6PrefixLen = null;
        if (preg_match_all('/inet6 ([0-9a-f:]+)\s+prefixlen\s+([0-9]+)/', $szConfig, $aMatchIpv6)) {
            for ($i = 0; $i < count($aMatchIpv6[0]); $i++) {
                $abIpv6Addr = MiscNet::Ipv6StringToBinary($aMatchIpv6[1][$i]);
                if ($abIpv6Addr === false || substr($abIpv6Addr, 0, 2) === "\xfe\x80") {
                    /* skip link-local */
                    $abIpv6Addr = false;
                    continue;
                }
                $dwIpv6PrefixLen = intval($aMatchIpv6[2][$i]);
                break;
            }
        }
        $abMacAddress = null;
        if (preg_match('/ether ((?:[0-9a-f]{2}:){5}[0-9a-f]{2})/', $szConfig, $aMatchMacAddress)) {
            $abMacAddress =
                chr(hexdec(substr($aMatchMacAddress[1], 0, 2))) .
                chr(hexdec(substr($aMatchMacAddress[1], 3, 2))) .
                chr(hexdec(substr($aMatchMacAddress[1], 6, 2))) .
                chr(hexdec(substr($aMatchMacAddress[1], 9, 2))) .
                chr(hexdec(substr($aMatchMacAddress[1], 12, 2))) .
                chr(hexdec(substr($aMatchMacAddress[1], 15, 2)));
        }
        return new InterfaceInfo(
            MiscNet::Ipv4StringToDword($szIpAddr),
            MiscNet::Ipv4StringToDword($szNetmask),
            $abIpv6Addr,
            $dwIpv6PrefixLen,
            $abMacAddress
        );
    }
}

?>