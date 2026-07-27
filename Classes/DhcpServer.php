<?php

namespace VVTS\Classes;

require_once(dirname(__FILE__) . "/../autoload.php");

use \VVTS\Classes\MainLoop;
use \VVTS\Classes\MiscNet;
use \VVTS\Classes\Subscribable;
use \VVTS\Interfaces\IUnblockable;
use \VVTS\Types\InterfaceInfo;
use \VVTS\Types\StaticRoute;

class DhcpServer extends Subscribable implements IUnblockable {
    var $szInterface;
    var $hProcess;
    var $hProcessStdout;
    var $hProcessStderr;
    var $szTmpfile;
    var $dwAvoid;
    var $dwLeaseTime;
    var $szDomain;
    var $szWpadUrl;
    var $szCaptivePortalUri;
    var $dwDns;
    var $dwRouter;
    var $dwStaticRouteOption;
    var $aStaticRoutes;

    function __construct() {
        parent::__construct();
        $this->dwStaticRouteOption = 121;
        $this->aStaticRoutes = [];

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

    function Onunblock($hSocket) {
        $abBuf = fgets($hSocket, 1024);
        if ($abBuf === "" || $abBuf === false) {
            printf("[i] udhcpd process ended\n");
            $this->Signal("dhcp4_err", "udhcpd process ended (interface down?)");
            $this->Teardown();
            return;
        }
        printf("udhcpd: %s", $abBuf);

        if (strpos($abBuf, "udhcpd: started") !== false) {
            printf("[i] udhcp up\n");
            $this->Signal("dhcp4_up");
        }

        if (preg_match('/sending ACK to ([0-9\.]+)/', $abBuf, $aMatchAck)) {
            $this->Signal("dhcp4_client_connected", $aMatchAck[1]);
        }
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
        if ($this->szTmpfile !== null) {
            unlink($this->szTmpfile);
            $this->szTmpfile = null;
        }

        $this->CancelAllSubscriptions();
    }

    static function EliminateFromInterval(&$aInterval, $dwEliminate) {
        if (($dwEliminate >= $aInterval[0]) && ($dwEliminate <= $aInterval[1])) {
            if (($dwEliminate - $aInterval[0]) < ($aInterval[1] - $dwEliminate)) {
                $aInterval[0] = $dwEliminate + 1;
            } else {
                $aInterval[1] = $dwEliminate - 1;
            }
        }
    }

    function SetStaticRoute($dwAddress, $dwNetmask, $dwGateway) {
        array_push($this->aStaticRoutes, new StaticRoute($dwAddress, $dwNetmask, $dwGateway));
    }

    function ClearStaticRoutes() {
        $this->aStaticRoutes = [];
    }

    function Reload() {
        /* TODO: make less hacky */
        $aSubscribersBackup = $this->aSubscribers;
        $this->Teardown();
        $this->aSubscribers = $aSubscribersBackup;
        $this->Bringup();
    }

    function Bringup() {
        if ($this->szInterface === null) {
            $this->Signal("dhcp4_err", "Please set szInterface before invoking Bringup()");
            $this->Teardown();
            return;
        }

        $oInterfaceInfo = InterfaceInfo::FromInterface($this->szInterface);
        if ($oInterfaceInfo === null) {
            $this->Signal("dhcp4_err", "Could not retrieve network interface information for " . $this->szInterface);
            $this->Teardown();
            return;
        }

        $dwNetmask = $this->dwNetmask != null ? $this->dwNetmask : $oInterfaceInfo->dwNetmask;
        $dwSubnet = $oInterfaceInfo->dwIpAddr & $dwNetmask;
        $dwBroadcast = ($dwSubnet | ~$dwNetmask) & 0xffffffff;

        $aInterval = [$dwSubnet+1, $dwBroadcast-1];
        self::EliminateFromInterval($aInterval, $oInterfaceInfo->dwIpAddr);
        if ($this->dwAvoid != null) {
            self::EliminateFromInterval($aInterval, $this->dwAvoid);
        }

        $szConfig = "";
        $szConfig .= "start " . MiscNet::DwordToIpv4String($aInterval[0]) . "\n";
        $szConfig .= "end " . MiscNet::DwordToIpv4String($aInterval[1]) . "\n";
        $szConfig .= "interface " . $this->szInterface . "\n";
        if ($this->dwDns != null) {
            $szConfig .= "opt dns " . MiscNet::DwordToIpv4String($this->dwDns) . "\n";
        }
        if ($this->dwNetmask != null) {
            $szConfig .= "opt subnet " . MiscNet::DwordToIpv4String($this->dwNetmask) . "\n";
        } else {
            $szConfig .= "opt subnet " . MiscNet::DwordToIpv4String($oInterfaceInfo->dwNetmask) . "\n";
        }
        if ($this->dwRouter != null) {
            $szConfig .= "opt router " . MiscNet::DwordToIpv4String($this->dwRouter) . "\n";
        }
        if (count($this->aStaticRoutes) != 0) {
            $szStaticRouteValue = "";
            foreach($this->aStaticRoutes as $oRoute) {
                $dwPrefixLen = MiscNet::NetmaskToPrefixLength($oRoute->dwNetmask);
                $dwByteLen = ($dwPrefixLen + 7) >> 3;
                $szStaticRouteValue .= sprintf("%02x", $dwPrefixLen);
                for($i = 0; $i < $dwByteLen; $i++) {
                    $bByteValue = ($oRoute->dwAddress >> (24 - ($i << 3))) & 0xff;
                    if (($dwPrefixLen >> 3) == $i) {
                        $bByteValue &= (0xff00 >> ($dwPrefixLen & 7));
                    }
                    $szStaticRouteValue .= sprintf("%02x", $bByteValue);
                }
                $szStaticRouteValue .= sprintf("%02x", ($oRoute->dwGateway >> 24) & 0xff);
                $szStaticRouteValue .= sprintf("%02x", ($oRoute->dwGateway >> 16) & 0xff);
                $szStaticRouteValue .= sprintf("%02x", ($oRoute->dwGateway >> 8) & 0xff);
                $szStaticRouteValue .= sprintf("%02x", $oRoute->dwGateway & 0xff);
            }
            $szConfig .= "opt " . intval($this->dwStaticRouteOption) . " " . $szStaticRouteValue . "\n";
        }
        if ($this->szDomain !== null) {
            $szConfig .= "opt domain " . $this->szDomain . "\n";
        }
        if ($this->szWpadUrl !== null) {
            $szConfig .= "opt wpad " . $this->szWpadUrl . "\n";
        }
        if ($this->szCaptivePortalUri !== null) {
            $szConfig .= "opt 114 " . bin2hex($this->szCaptivePortalUri) . "\n";
        }
        $szConfig .= "opt lease " . (($this->dwLeaseTime === null) ? "864000" : strval($this->dwLeaseTime)) . "\n";

        $aSpec = [
            0 => ["file", "/dev/null", "r"],
            1 => ["pipe", "w"],
            2 => ["pipe", "w"]
        ];

        $this->szTmpfile = tempnam("/tmp", "udhcpd_");
        file_put_contents($this->szTmpfile, $szConfig);
        $this->hProcess = proc_open("exec udhcpd -f " . escapeshellarg($this->szTmpfile), $aSpec, $aPipes);
        $this->hProcessStdout = $aPipes[1];
        $this->hProcessStderr = $aPipes[2];
    }
}

?>
