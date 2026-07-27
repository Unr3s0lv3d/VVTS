<?php

namespace VVTS\Classes;

require_once(dirname(__FILE__) . "/../autoload.php");

use \VVTS\Classes\MainLoop;
use \VVTS\Classes\ScriptEngine;
use \VVTS\Classes\HttpClient;
use \VVTS\Types\ScriptInvokeError;
use \VVTS\Types\ScriptState;
use \VVTS\Types\ScriptStringLiteral;
use \VVTS\Types\ScriptVoid;
use \VVTS\Interfaces\IScriptOpaque;
use \VVTS\Interfaces\IUnblockable;

class RemoteProxy implements IScriptOpaque, IUnblockable {
    var $szServerHost;
    var $wServerPort;
    var $bServerSecure;
    var $szSecret;
    var $oHttpClient;
    var $aTransitions;
    var $szMode;
    var $szLocalAddr;
    var $szDirect;
    var $hLocalProcess;
    var $hLocalStdout;
    var $hLocalStderr;

    function __construct() {
        $this->aTransitions = [];
        $this->szServerHost = null;
        $this->szSecret = null;
        $this->szMode = "remote";
        $this->szLocalAddr = null;
        $this->szDirect = null;
        $this->hLocalProcess = null;
        $this->hLocalStdout = null;
        $this->hLocalStderr = null;
    }

    function Sockets() {
        $aStreams = [];
        if ($this->hLocalStdout != null) {
            array_push($aStreams, $this->hLocalStdout);
        }
        if ($this->hLocalStderr != null) {
            array_push($aStreams, $this->hLocalStderr);
        }
        return $aStreams;
    }

    function Onunblock($hSocket) {
        $abBuf = fgets($hSocket, 1024);
        if ($abBuf === "" || $abBuf === false) {
            return;
        }
        printf("proxy: %s", $abBuf);
    }

    function StateMachineSet_server($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("server must be of type string");
        }
        if (!preg_match('/^(https?):\/\/([^\/]+)/', $oValue->szLiteral, $aMatch)) {
            throw new ScriptInvokeError("invalid server URL: " . $oValue->szLiteral);
        }
        $this->bServerSecure = $aMatch[1] === 'https';
        $szHostPort = $aMatch[2];
        if (strpos($szHostPort, ':') !== false) {
            list($this->szServerHost, $wPort) = explode(':', $szHostPort, 2);
            $this->wServerPort = (int)$wPort;
        } else {
            $this->szServerHost = $szHostPort;
            $this->wServerPort = $this->bServerSecure ? 443 : 80;
        }
    }

    function StateMachineSet_secret($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("secret must be of type string");
        }
        $this->szSecret = $oValue->szLiteral;
    }

    function StateMachineSet_mode($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("mode must be of type string");
        }
        if ($oValue->szLiteral !== "remote" && $oValue->szLiteral !== "local") {
            throw new ScriptInvokeError("mode must be \"remote\" or \"local\", got: " . $oValue->szLiteral);
        }
        $this->szMode = $oValue->szLiteral;
    }

    function StateMachineSet_local_addr($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("local_addr must be of type string");
        }
        if (!preg_match('/^[^:]+:[0-9]+$/', $oValue->szLiteral)) {
            throw new ScriptInvokeError("local_addr must be in host:port format, got: " . $oValue->szLiteral);
        }
        $this->szLocalAddr = $oValue->szLiteral;
    }

    function StateMachineSet_direct($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("direct must be of type string");
        }
        $this->szDirect = ($oValue->szLiteral === "") ? null : $oValue->szLiteral;
    }

    function PerformTransition($szWhich) {
        if (isset($this->aTransitions[$szWhich])) {
            $oTransition = $this->aTransitions[$szWhich];
            $this->aTransitions = [];
            ScriptEngine::GetInstance()->EnterState($oTransition);
        }
    }

    function OnHttpResponse($szBody) {
        if ($this->oHttpClient !== null) {
            $this->oHttpClient->CancelAllSubscriptions();
        }
        $oJson = @json_decode($szBody);
        if (is_object($oJson) && isset($oJson->ok) && $oJson->ok) {
            $this->PerformTransition("success");
        } else {
            $szError = (is_object($oJson) && isset($oJson->error)) ? $oJson->error : "unknown error";
            ScriptEngine::GetInstance()->SetErrstr("proxy error: " . $szError);
            $this->PerformTransition("error");
        }
    }

    function OnHttpError($szErrstr) {
        if ($this->oHttpClient !== null) {
            $this->oHttpClient->CancelAllSubscriptions();
        }
        ScriptEngine::GetInstance()->SetErrstr("http error: " . $szErrstr);
        $this->PerformTransition("error");
    }

    function BringUpLocal() {
        list($szHost, $szPort) = explode(':', $this->szLocalAddr, 2);
        $wPort = (int)$szPort;

        $szPyPath = dirname(__FILE__) . "/../src/proxy.py";
        if (!file_exists($szPyPath)) {
            ScriptEngine::GetInstance()->SetErrstr("proxy.py not found at " . $szPyPath);
            $this->PerformTransition("error");
            return;
        }

        $aSpec = [
            0 => ["file", "/dev/null", "r"],
            1 => ["pipe", "w"],
            2 => ["pipe", "w"]
        ];

        $this->hLocalProcess = proc_open(
            "exec python3 " . escapeshellarg($szPyPath) . " " . $wPort,
            $aSpec,
            $aPipes
        );
        $this->hLocalStdout = $aPipes[1];
        $this->hLocalStderr = $aPipes[2];
        MainLoop::GetInstance()->RegisterObject($this);

        $bStarted = false;
        for ($i = 0; $i < 20; $i++) {
            usleep(100000);
            $hSock = @fsockopen("127.0.0.1", $wPort, $errno, $errstr, 1);
            if ($hSock !== false) {
                fclose($hSock);
                $bStarted = true;
                break;
            }
        }

        if (!$bStarted) {
            ScriptEngine::GetInstance()->SetErrstr("local proxy failed to start on port " . $wPort);
            $this->PerformTransition("error");
            return;
        }

        printf("[i] local proxy started on port %d\n", $wPort);

        $szQuery = "/?configure_wpad"
            . "&proxy_host=" . urlencode($szHost)
            . "&proxy_port=" . $wPort;
        if ($this->szDirect !== null) {
            $szQuery .= "&direct=" . urlencode($this->szDirect);
        }

        $this->oHttpClient = new HttpClient($this->szServerHost, $this->wServerPort, $this->bServerSecure);
        $this->oHttpClient->Subscribe("http_response", $this, "OnHttpResponse", null, true);
        $this->oHttpClient->Subscribe("http_error", $this, "OnHttpError", null, true);
        $this->oHttpClient->SendRequest($szQuery, 10000, ["X-API-Secret: " . $this->szSecret]);
    }

    function StateMachineInvoke_bring_up(...$aArguments) {
        if (count($aArguments) !== 2) {
            throw new ScriptInvokeError("bring_up requires two arguments");
        }
        if (!($aArguments[0] instanceof ScriptState) || !($aArguments[1] instanceof ScriptState)) {
            throw new ScriptInvokeError("bring_up requires a success and an error state");
        }
        if ($this->szServerHost === null) {
            throw new ScriptInvokeError("please set server before calling bring_up()");
        }
        if ($this->szSecret === null) {
            $oSecret = ScriptEngine::GetInstance()->aVariables["server_secret"] ?? null;
            if ($oSecret instanceof ScriptStringLiteral && $oSecret->szLiteral !== "") {
                $this->szSecret = $oSecret->szLiteral;
            } else {
                throw new ScriptInvokeError("please set secret or server_secret before calling bring_up()");
            }
        }
        if ($this->szMode === "local" && $this->szLocalAddr === null) {
            throw new ScriptInvokeError("please set local_addr before calling bring_up() in local mode");
        }

        $this->aTransitions["success"] = ScriptEngine::GetInstance()->RegisterStateTransition($aArguments[0]);
        $this->aTransitions["error"] = ScriptEngine::GetInstance()->RegisterStateTransition($aArguments[1]);

        if ($this->szMode === "local") {
            $this->BringUpLocal();
        } else {
            $this->oHttpClient = new HttpClient($this->szServerHost, $this->wServerPort, $this->bServerSecure);
            $this->oHttpClient->Subscribe("http_response", $this, "OnHttpResponse", null, true);
            $this->oHttpClient->Subscribe("http_error", $this, "OnHttpError", null, true);
            $this->oHttpClient->SendRequest("/?start_proxy", 10000, ["X-API-Secret: " . $this->szSecret]);
        }

        return new ScriptVoid();
    }

    function Teardown() {
        if ($this->oHttpClient !== null) {
            $this->oHttpClient->CancelAllSubscriptions();
            $this->oHttpClient = null;
        }

        if ($this->hLocalStdout != null) {
            fclose($this->hLocalStdout);
            $this->hLocalStdout = null;
        }
        if ($this->hLocalStderr != null) {
            fclose($this->hLocalStderr);
            $this->hLocalStderr = null;
        }
        if ($this->hLocalProcess != null) {
            $aStatus = proc_get_status($this->hLocalProcess);
            if (isset($aStatus["running"]) && $aStatus["running"]) {
                posix_kill($aStatus["pid"], SIGTERM);
            }
            proc_close($this->hLocalProcess);
            $this->hLocalProcess = null;
        }

        if ($this->szServerHost !== null && $this->szSecret !== null) {
            $szScheme = $this->bServerSecure ? 'https' : 'http';
            $szPortSuffix = (($this->bServerSecure && $this->wServerPort === 443) || (!$this->bServerSecure && $this->wServerPort === 80))
                ? '' : ':' . $this->wServerPort;
            if ($this->szMode === "local") {
                $szUrl = $szScheme . '://' . $this->szServerHost . $szPortSuffix . '/?unconfigure_wpad';
            } else {
                $szUrl = $szScheme . '://' . $this->szServerHost . $szPortSuffix . '/?stop_proxy';
            }
            @file_get_contents($szUrl, false, stream_context_create([
                'ssl'  => ['verify_peer' => false, 'verify_peer_name' => false],
                'http' => ['timeout' => 5, 'header' => 'X-API-Secret: ' . $this->szSecret]
            ]));
        }
    }
}

?>
