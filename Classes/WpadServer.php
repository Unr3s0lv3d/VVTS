<?php

namespace VVTS\Classes;

require_once(dirname(__FILE__) . "/../autoload.php");

use \VVTS\Classes\MainLoop;
use \VVTS\Classes\Subscribable;
use \VVTS\Interfaces\IUnblockable;

class WpadServer extends Subscribable implements IUnblockable {
    var $szBindAddr;
    var $szProxyAddr;
    var $aDirectHosts;
    var $aProxyHosts;
    var $szTmpDir;
    var $hProcess;
    var $hProcessStdout;
    var $hProcessStderr;

    function __construct() {
        parent::__construct();
        $this->aDirectHosts = [];
        $this->aProxyHosts = [];
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
            printf("[i] wpad php server process ended\n");
            $this->Signal("wpad_err", "php server process ended (port 80 in use?)");
            $this->Teardown();
            return;
        }
        printf("wpad: %s", $abBuf);

        if (strpos($abBuf, "started") !== false) {
            printf("[i] wpad server up\n");
            $this->Signal("wpad_up");
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
        if ($this->szTmpDir !== null) {
            @unlink($this->szTmpDir . "/wpad.dat");
            @rmdir($this->szTmpDir);
            $this->szTmpDir = null;
        }

        $this->CancelAllSubscriptions();
    }

    function BringUp() {
        if ($this->szBindAddr === null) {
            $this->Signal("wpad_err", "Please set szBindAddr before invoking BringUp()");
            return;
        }
        if ($this->szProxyAddr === null) {
            $this->Signal("wpad_err", "Please set szProxyAddr before invoking BringUp()");
            return;
        }

        $szPacContent = "function FindProxyForURL(url, host) {\n";
        foreach($this->aDirectHosts as $szHost) {
            if (strpos($szHost, "*") !== false) {
                $szPacContent .= "    if (shExpMatch(host, \"" . $szHost . "\")) return \"DIRECT\";\n";
            } else {
                $szPacContent .= "    if (host == \"" . $szHost . "\") return \"DIRECT\";\n";
            }
        }
        foreach($this->aProxyHosts as $szHost => $szProxy) {
            if (strpos($szHost, "*") !== false) {
                $szPacContent .= "    if (shExpMatch(host, \"" . $szHost . "\")) return \"PROXY " . $szProxy . "\";\n";
            } else {
                $szPacContent .= "    if (host == \"" . $szHost . "\") return \"PROXY " . $szProxy . "\";\n";
            }
        }
        $szPacContent .= "    return \"PROXY " . $this->szProxyAddr . "\";\n" .
                         "}\n";

        $this->szTmpDir = sys_get_temp_dir() . "/wpad_" . uniqid();
        if (!mkdir($this->szTmpDir)) {
            $this->Signal("wpad_err", "Could not create temporary directory");
            return;
        }
        file_put_contents($this->szTmpDir . "/wpad.dat", $szPacContent);

        $aSpec = [
            0 => ["file", "/dev/null", "r"],
            1 => ["pipe", "w"],
            2 => ["pipe", "w"]
        ];

        $this->hProcess = proc_open(
            "exec php -S " . escapeshellarg($this->szBindAddr . ":80") . " -t " . escapeshellarg($this->szTmpDir),
            $aSpec,
            $aPipes
        );
        $this->hProcessStdout = $aPipes[1];
        $this->hProcessStderr = $aPipes[2];
    }
}

?>
