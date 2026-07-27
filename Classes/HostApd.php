<?php

namespace VVTS\Classes;

require_once(dirname(__FILE__) . "/../autoload.php");

use \VVTS\Classes\MainLoop;
use \VVTS\Classes\Subscribable;
use \VVTS\Interfaces\IUnblockable;

class HostApd extends Subscribable implements IUnblockable {
    var $szInterface;
    var $szApInterface;
    var $hProcess;
    var $hProcessStdout;
    var $hProcessStderr;
    var $szTmpfile;
    var $bIsUp;
    var $szDriver;
    var $szSsid;
    var $szPassphrase;
    var $dwChannel;

    function __construct($szInterface) {
        parent::__construct();
        $this->szInterface = $szInterface;
        $this->bIsUp = false;

        MainLoop::GetInstance()->RegisterObject($this);
    }

    function BringUp() {
        $aSpec = [
            0 => ["file", "/dev/null", "r"],
            1 => ["pipe", "w"],
            2 => ["pipe", "w"]
        ];

        $szWifiInterfaces = shell_exec("iw dev");
        for ($i = 0; ; $i++) {
            if (preg_match('/^\s*Interface\s+vvts' . intval($i) . '/im', $szWifiInterfaces)) {
                continue;
            }
            break;
        }
        $this->szApInterface = "vvts" . $i;

        printf("[i] creating interface %s\n", $this->szApInterface);
        shell_exec(
            "iw dev " . escapeshellarg($this->szInterface) . " " .
            "interface add " . escapeshellarg($this->szApInterface) . " type __ap " .
            "2>/dev/null"
        );
        /* tell NetworkManager to leave this interface alone */
        shell_exec("nmcli device set " . escapeshellarg($this->szApInterface) . " managed no 2>/dev/null");
        /* avoid race condition where both the kernel and vvts assign link-local address */
        shell_exec("ip link set dev " . escapeshellarg($this->szApInterface) . " addrgenmode none");

        $szDriver = ($this->szDriver === null) ? "nl80211" : $this->szDriver;
        $szSsid = ($this->szSsid === null) ? "Free WiFi😍" : $this->szSsid;
        $dwChannel = 4;
        if ($this->dwChannel === null) {
            /*
             * we prefer to be on the same channel as the original interface
             * as many radios only support operating on a single frequency
             */
            $szWifiInfo = shell_exec("iw " . escapeshellarg($this->szInterface) . " info 2>/dev/null");
            if (preg_match('/^\s*channel ([0-9]+)/im', $szWifiInfo, $aMatchChannel)) {
                $dwChannel = intval($aMatchChannel[1]);
            } else {
                $dwChannel = 6;
            }
        } else {
            $dwChannel = $this->dwChannel;
        }

        $szConfig = "";
        $szConfig .= "interface=" . $this->szApInterface . "\n";
        $szConfig .= "driver=" . $szDriver . "\n";
        $szConfig .= "logger_syslog=-1\n";
        $szConfig .= "logger_syslog_level=2\n";
        $szConfig .= "logger_stdout=-1\n";
        $szConfig .= "logger_stdout_level=2\n";
        $szConfig .= "ctrl_interface=/var/run/hostapd\n";
        $szConfig .= "ctrl_interface_group=0\n";
        $szConfig .= "ssid=" . $szSsid . "\n";
        $szConfig .= "hw_mode=" . (($dwChannel > 14) ? "a" : "g") . "\n";
        $szConfig .= "channel=" . $dwChannel . "\n";
        $szConfig .= "beacon_int=100\n";
        $szConfig .= "dtim_period=2\n";
        $szConfig .= "max_num_sta=255\n";
        $szConfig .= "rts_threshold=-1\n";
        $szConfig .= "fragm_threshold=-1\n";
        $szConfig .= "macaddr_acl=0\n";
        $szConfig .= "auth_algs=3\n";
        $szConfig .= "ignore_broadcast_ssid=0\n";
        $szConfig .= "wmm_enabled=1\n";
        $szConfig .= "wmm_ac_bk_cwmin=4\n";
        $szConfig .= "wmm_ac_bk_cwmax=10\n";
        $szConfig .= "wmm_ac_bk_aifs=7\n";
        $szConfig .= "wmm_ac_bk_txop_limit=0\n";
        $szConfig .= "wmm_ac_bk_acm=0\n";
        $szConfig .= "wmm_ac_be_aifs=3\n";
        $szConfig .= "wmm_ac_be_cwmin=4\n";
        $szConfig .= "wmm_ac_be_cwmax=10\n";
        $szConfig .= "wmm_ac_be_txop_limit=0\n";
        $szConfig .= "wmm_ac_be_acm=0\n";
        $szConfig .= "wmm_ac_vi_aifs=2\n";
        $szConfig .= "wmm_ac_vi_cwmin=3\n";
        $szConfig .= "wmm_ac_vi_cwmax=4\n";
        $szConfig .= "wmm_ac_vi_txop_limit=94\n";
        $szConfig .= "wmm_ac_vi_acm=0\n";
        $szConfig .= "wmm_ac_vo_aifs=2\n";
        $szConfig .= "wmm_ac_vo_cwmin=2\n";
        $szConfig .= "wmm_ac_vo_cwmax=3\n";
        $szConfig .= "wmm_ac_vo_txop_limit=47\n";
        $szConfig .= "wmm_ac_vo_acm=0\n";
        $szConfig .= "eapol_key_index_workaround=0\n";
        $szConfig .= "eap_server=0\n";
        $szConfig .= "own_ip_addr=127.0.0.1\n";
        if ($this->szPassphrase !== null) {
            $szConfig .= "wpa=2\n";
            $szConfig .= "wpa_passphrase=". $this->szPassphrase . "\n";
        }

        $this->szTmpfile = tempnam("/tmp", "hostapd_");
        file_put_contents($this->szTmpfile, $szConfig);

        $this->hProcess = proc_open("exec hostapd -d " . escapeshellarg($this->szTmpfile), $aSpec, $aPipes);
        $this->hProcessStdout = $aPipes[1];
        $this->hProcessStderr = $aPipes[2];
    }

    function Sockets() {
        if ($this->hProcessStdout != null) {
            return [$this->hProcessStdout];
        }
        if ($this->hProcessStderr != null) {
            return [$this->hProcessStderr];
        }
        return [];
    }

    function Onunblock($hSocket) {
        $abBuf = fgets($hSocket, 1024);
        if ($abBuf === "" || $abBuf === false) {
            printf("[i] hostapd process ended\n");
            $this->Signal("ap_err", "Hostapd process ended (interface down?)");
            $this->Teardown();
            return;
        }
        if (strpos($abBuf, "Setup of interface done") !== false) {
            printf("[i] hostap setup done\n");
            $this->bIsUp = true;
            $this->Signal("ap_up");
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

        shell_exec("iw dev " . escapeshellarg($this->szApInterface) . " del 2>/dev/null");
        if ($this->szTmpfile !== null) {
            unlink($this->szTmpfile);
            $this->szTmpfile = null;
        }
        $this->CancelAllSubscriptions();
        $this->bIsUp = false;
    }

    function GetApInterface() {
        if (!$this->bIsUp) {
            return null;
        }
        return $this->szApInterface;
    }
}

?>