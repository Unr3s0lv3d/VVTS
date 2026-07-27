<?php

namespace VVTS\Classes;

require_once(dirname(__FILE__) . "/../autoload.php");

use \VVTS\Classes\MainLoop;
use \VVTS\Classes\MiscNet;
use \VVTS\Classes\Subscribable;
use \VVTS\Types\InterfaceInfo;
use \VVTS\Types\StaticIpv6Route;
use \VVTS\Interfaces\IUnblockable;

class SlaacAdvertiser extends Subscribable implements IUnblockable {
    var $szInterface;
    var $hProcess;
    var $hProcessStdout;
    var $hProcessStderr;
    var $szTmpfile;
    var $szDomain;
    var $abDns;
    var $dwLifetime;
    var $aStaticRoutes;
    var $bNat64Enable;

    function __construct() {
        parent::__construct();
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
            printf("[i] radvd process ended\n");
            $this->Signal("slaac_err", "radvd process ended (interface down?)");
            $this->Teardown();
            return;
        }
        printf("radvd: %s", $abBuf);

        if (preg_match('/config file, [^,]*, syntax ok/', $abBuf)) {
            printf("[i] slaac up\n");
            $this->Signal("slaac_up");
        }

        if (preg_match('/received NA from: ([0-9a-f:]+)$/', $abBuf, $aMatchNa)) {
            $this->Signal("slaac_renew", $aMatchNa[1]);
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

    function SetStaticRoute($abAddress, $dwPrefixLen) {
        array_push($this->aStaticRoutes, new StaticIpv6Route($abAddress, $dwPrefixLen));
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
            $this->Signal("slaac_err", "Please set szInterface before invoking Bringup()");
            $this->Teardown();
            return;
        }

        $oInterfaceInfo = InterfaceInfo::FromInterface($this->szInterface);
        if ($oInterfaceInfo === null) {
            $this->Signal("slaac_err", "Could not retrieve network interface information for " . $this->szInterface);
            $this->Teardown();
            return;
        } else if ($oInterfaceInfo->abIpv6Addr === null) {
            $this->Signal("slaac_err", "No ipv6 address set for interface " . $this->szInterface);
            $this->Teardown();
            return;
        }

        /* apply netmask to ipv6 address */
        $abSubnet = "";
        for ($i = 0; $i < 16; $i++) {
            if ($i < ($oInterfaceInfo->dwIpv6PrefixLen >> 3)) {
                $abSubnet .= $oInterfaceInfo->abIpv6Addr[$i];
            } else if ($i == ($oInterfaceInfo->dwIpv6PrefixLen >> 3)) {
                $abSubnet .= chr(ord($oInterfaceInfo->abIpv6Addr[$i]) & (0xff00 >> ($oInterfaceInfo->dwIpv6PrefixLen & 7)));
            } else {
                $abSubnet .= "\x00";
            }
        }

        $dwLifetime = ($this->dwLifetime === null) ? 900 : $this->dwLifetime;
        $szConfig = "";
        $szConfig .= "interface " . $this->szInterface ." {\n";
        $szConfig .= "    AdvSendAdvert on;\n";
        $szConfig .= "    AdvManagedFlag off;\n";
        $szConfig .= "    AdvDefaultPreference high;\n";
        $szConfig .= "    AdvDefaultLifetime " . intval($dwLifetime) . ";\n";
        if (intval($dwLifetime) < 600) {
            $szConfig .= "    MinRtrAdvInterval " . intval(($dwLifetime * 3) / 4) . ";\n";
            $szConfig .= "    MaxRtrAdvInterval " . intval($dwLifetime) . ";\n";
        }
        /* RemoveAdvOnExit means sending out one last RA with zero lifetime -> makes android disconnect */
        $szConfig .= "    RemoveAdvOnExit off;\n";
        $szConfig .= "    AdvOtherConfigFlag off;\n";
        $szConfig .= "    prefix " . MiscNet::BinaryToIpv6String($abSubnet) . "/" . intval($oInterfaceInfo->dwIpv6PrefixLen) . " {\n";
        $szConfig .= "        AdvOnLink on;\n";
        $szConfig .= "        AdvAutonomous on;\n";
        $szConfig .= "    };\n";
        /* This is the PREF64 configuration for the CLAT discovery */
        /* The Android device will see this and start its internal CLAT */
        if ($this->bNat64Enable) {
            $szConfig .= "    nat64prefix 64:ff9b::/96 { };\n";
        }
        foreach($this->aStaticRoutes as $oRoute) {
            /* apply netmask to ipv6 address */
            $abRouteSubnet = "";
            for ($i = 0; $i < 16; $i++) {
                if ($i < ($oRoute->dwPrefixLen >> 3)) {
                    $abRouteSubnet .= $oRoute->abAddress[$i];
                } else if ($i == ($oRoute->dwPrefixLen >> 3)) {
                    $abRouteSubnet .= chr(ord($oRoute->abAddress[$i]) & (0xff00 >> ($oRoute->dwPrefixLen & 7)));
                } else {
                    $abRouteSubnet .= "\x00";
                }
            }
            $szConfig .= "    route " . MiscNet::BinaryToIpv6String($abRouteSubnet) . "/" . intval($oRoute->dwPrefixLen) . " { };\n";
        }
        if (isset($this->abDns)) {
            $szConfig .= "    RDNSS " . MiscNet::BinaryToIpv6String($this->abDns) . " { };\n";
        }
        if ($this->szDomain !== null) {
            $szConfig .= "  DNSSL " . $this->szDomain . " { };\n";
        }

        $szConfig .= "};\n";

        $aSpec = [
            0 => ["file", "/dev/null", "r"],
            1 => ["pipe", "w"],
            2 => ["pipe", "w"]
        ];

        $this->szTmpfile = tempnam(sys_get_temp_dir(), "radvd_");
        file_put_contents($this->szTmpfile, $szConfig);
        $this->hProcess = proc_open("exec " . escapeshellarg(dirname(__FILE__) . "/../external/radvd-2.20/radvd") . " -d 3 -m stderr -n -C " . escapeshellarg($this->szTmpfile), $aSpec, $aPipes);
        $this->hProcessStdout = $aPipes[1];
        $this->hProcessStderr = $aPipes[2];
    }
}

?>