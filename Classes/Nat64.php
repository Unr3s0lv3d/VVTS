<?php

namespace VVTS\Classes;

require_once(dirname(__FILE__) . "/../autoload.php");

use \VVTS\Classes\MainLoop;
use \VVTS\Classes\MiscNet;
use \VVTS\Classes\Subscribable;
use \VVTS\Interfaces\IUnblockable;
use \VVTS\Types\InterfaceInfo;

class Nat64 extends Subscribable implements IUnblockable {
    var $szInterface;
    var $szNat64Interface;
    var $hProcess;
    var $hProcessStdout;
    var $hProcessStderr;
    var $szTmpfile;
    var $abSubnet;

    function __construct() {
        parent::__construct();
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

    function IptablesDeconfigure() {
        MiscNet::IptablesDeinitBranch(true, "filter", "FORWARD", "VVTS_FORWARD_NAT64");
    }

    function IptablesConfigure() {
        MiscNet::IptablesInitBranch(true, "filter", "FORWARD", "VVTS_FORWARD_NAT64");
        shell_exec(
            "ip6tables" .
                " -A VVTS_FORWARD_NAT64" .
                " -s " . escapeshellarg(MiscNet::BinaryToIpv6String($this->abSubnet) . "/" . intval($this->dwIpv6PrefixLen)) .
                " -d 64:ff9b::/96" .
                " -j ACCEPT"
        );
        shell_exec(
            "ip6tables" .
                " -A VVTS_FORWARD_NAT64" .
                " -s 64:ff9b::/96" .
                " -d " . escapeshellarg(MiscNet::BinaryToIpv6String($this->abSubnet) . "/" . intval($this->dwIpv6PrefixLen)) .
                " -j ACCEPT"
        );
        shell_exec(
            "ip6tables" .
                " -A VVTS_FORWARD_NAT64" .
                " -d 64:ff9b::/96" .
                " -j DROP"
        );
        shell_exec(
            "ip6tables" .
                " -A VVTS_FORWARD_NAT64" .
                " -s 64:ff9b::/96" .
                " -j DROP"
        );
    }

    function Onunblock($hSocket) {
        $abBuf = fgets($hSocket, 1024);
        if ($abBuf === "" || $abBuf === false) {
            printf("[i] tayga process ended\n");
            $this->Signal("nat64_err", "tayga process ended (interface down?)");
            $this->Teardown();
            return;
        }
        printf("tayga: %s", $abBuf);

        if (preg_match('/Loaded [0-9]+ dynamic map(?:s)? from /', $abBuf, $aMatchTayga)) {
            /* set ip addresses as exptected by tayga (it doesn't do this on its own) */
            shell_exec("ifconfig " . escapeshellarg($this->szNat64Interface) . " up 192.168.255.1 netmask 255.255.255.255");
            shell_exec("ip -6 addr add fd67:c166:c737:ea24::1 dev " . escapeshellarg($this->szNat64Interface));
            shell_exec("ip route add 192.168.255.0/24 dev " . escapeshellarg($this->szNat64Interface));

            $szRouteTable = shell_exec("ip -6 route list");
            if (preg_match('/^64:ff9b::\/96 /', $szRouteTable)) {
                shell_exec("ip -6 route del 64:ff9b::/96 2>/dev/null");
            }
            shell_exec("ip -6 route add 64:ff9b::/96 dev " . escapeshellarg($this->szNat64Interface) . " 2>/dev/null");
            
            $this->IptablesConfigure();
            $this->Signal("nat64_up");
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

        $this->IptablesDeconfigure();
        shell_exec(escapeshellarg(dirname(__FILE__) . "/../external/tayga-0.9.5/tayga") . " -d --config " . escapeshellarg($this->szTmpfile) . " --rmtun 2>/dev/null");
        if ($this->szTmpfile !== null) {
            unlink($this->szTmpfile);
            $this->szTmpfile = null;
        }

        $this->CancelAllSubscriptions();
    }

    function Bringup() {
        if ($this->szInterface === null) {
            $this->Signal("nat64_err", "Please set szInterface before invoking Bringup()");
            $this->Teardown();
            return;
        }

        $oInterfaceInfo = InterfaceInfo::FromInterface($this->szInterface);
        if ($oInterfaceInfo === null) {
            $this->Signal("nat64_err", "Could not retrieve network interface information for " . $this->szInterface);
            $this->Teardown();
            return;
        } else if ($oInterfaceInfo->abIpv6Addr === null) {
            $this->Signal("nat64_err", "No ipv6 address set for interface " . $this->szInterface);
            $this->Teardown();
            return;
        }

        $this->abIpv6Addr = $oInterfaceInfo->abIpv6Addr;
        $this->dwIpv6PrefixLen = $oInterfaceInfo->dwIpv6PrefixLen;
        /* apply netmask to ip address to obtain subnet */
        $this->abSubnet = "";
        for ($i = 0; $i < 16; $i++) {
            if ($i < ($oInterfaceInfo->dwIpv6PrefixLen >> 3)) {
                $this->abSubnet .= $oInterfaceInfo->abIpv6Addr[$i];
            } else if ($i == ($oInterfaceInfo->dwIpv6PrefixLen >> 3)) {
                $this->abSubnet .= chr(ord($oInterfaceInfo->abIpv6Addr[$i]) & (0xff00 >> ($oInterfaceInfo->dwIpv6PrefixLen & 7)));
            } else {
                $this->abSubnet .= "\x00";
            }
        }

        $this->szNat64Interface = $this->szInterface . "_nat64";
        $szConfig = "";
        $szConfig .= "tun-device " . $this->szNat64Interface . "\n";
        $szConfig .= "ipv4-addr 192.168.255.1\n";
        $szConfig .= "ipv6-addr fd67:c166:c737:ea24::1\n";
        $szConfig .= "prefix 64:ff9b::/96\n";
        $szConfig .= "dynamic-pool 192.168.255.0/24\n";
        $szConfig .= "data-dir /var/spool/tayga\n";

        $aSpec = [
            0 => ["file", "/dev/null", "r"],
            1 => ["pipe", "w"],
            2 => ["pipe", "w"]
        ];

        $this->szTmpfile = tempnam(sys_get_temp_dir(), "tayga_");
        file_put_contents($this->szTmpfile, $szConfig);

        shell_exec(escapeshellarg(dirname(__FILE__) . "/../external/tayga-0.9.5/tayga") . " -d --config " . escapeshellarg($this->szTmpfile) . " --mktun 2>/dev/null");
        shell_exec("nmcli device set " . escapeshellarg($this->szNat64Interface) . " managed no 2>/dev/null");
        $this->hProcess = proc_open("exec " . escapeshellarg(dirname(__FILE__) . "/../external/tayga-0.9.5/tayga") . " -d --config " . escapeshellarg($this->szTmpfile), $aSpec, $aPipes);
        $this->hProcessStdout = $aPipes[1];
        $this->hProcessStderr = $aPipes[2];
    }
}

?>