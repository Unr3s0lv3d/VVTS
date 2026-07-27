<?php

namespace VVTS\Classes;

require_once(dirname(__FILE__) . "/../autoload.php");

use \VVTS\Classes\MainLoop;
use \VVTS\Classes\Subscribable;
use \VVTS\Interfaces\IUnblockable;

class ArpResponder extends Subscribable implements IUnblockable {
    var $szInterface;
    var $hProcess;
    var $hProcessHandle;

    function __construct($szInterface) {
        parent::__construct();
        $this->szInterface = $szInterface;
        $this->hProcessHandle = null;
        $this->hProcess = null;

        MainLoop::GetInstance()->RegisterObject($this);
    }

    function Sockets() {
        if ($this->hProcessHandle != null) {
            return [$this->hProcessHandle];
        }
        return [];
    }

    function Onunblock($hSocket) {
        $abBuf = fgets($hSocket, 1024);
        if ($abBuf === "" || $abBuf === false) {
            printf("[i] arpresponder process ended\n");
            $this->Signal("arp_err", "Arp responder process ended (interface down?)");
            $this->Teardown();
            return;
        }
        printf("arpresponder: %s", $abBuf);

        if (strpos($abBuf, "arpresponder running") !== false) {
            printf("[i] arpresponder up\n");
            $this->Signal("arp_up");
        }

        /* regexes below only match real neighbor advertisement/arp responses, not spoofed ones */
        if (preg_match('/^Neighbor Advertisement ([0-9a-f:]+) is at [0-9a-f:]+\s*(\(spoofed\))?$/m', $abBuf, $aMatchNeigh)) {
            $this->Signal(empty($aMatchNeigh[2]) ? "peer_is_up" : "peer_spoofed", $aMatchNeigh[1]);
        } else if (preg_match('/([0-9\.]+) is at ([0-9a-f:]+)\s*(\(spoofed\))?$/m', $abBuf, $aMatchArp)) {
            $this->Signal(empty($aMatchArp[2]) ? "peer_is_up" : "peer_spoofed", $aMatchArp[1]);
        }
    }

    function Teardown() {
        if ($this->hProcessHandle != null) {
            fclose($this->hProcessHandle);
            $this->hProcessHandle = null;
        }
        if ($this->hProcess != null) {
            $aStatus = proc_get_status($this->hProcess);
            if (isset($aStatus["running"]) && $aStatus["running"]) {
                posix_kill($aStatus["pid"], SIGTERM);
            }
            proc_close($this->hProcess);
            $this->hProcess = null;
        }
        $this->CancelAllSubscriptions();
    }

    function Bringup() {
        $aSpec = [
            0 => ["file", "/dev/null", "r"],
            1 => ["pipe", "w"]
        ];

        $this->hProcess = proc_open("exec " . escapeshellarg(dirname(__FILE__) . "/../src/arpresponder") . " " . escapeshellarg($this->szInterface) . " 2>&1", $aSpec, $aPipes);
        $this->hProcessHandle = $aPipes[1];
    }
}

?>