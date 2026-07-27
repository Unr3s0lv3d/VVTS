<?php

namespace VVTS\Classes;

require_once(dirname(__FILE__) . "/../autoload.php");

use \VVTS\Classes\MainLoop;
use \VVTS\Classes\Subscribable;
use \VVTS\Interfaces\IUnblockable;

define("STATE_DISCONNECTED", 0);
define("STATE_CONNECTED", 1);
define("STATE_HEADERS_SENT", 2);
define("STATE_HEADERS_RECEIVED", 3);

class HttpClient extends Subscribable implements IUnblockable {
    var $dwState;
    var $hSocket;
    var $szHttpData;
    var $dwBytesLeft;
    var $szHost;
    var $wPort;
    var $bSecure;

    function __construct($szHost, $wPort, $bSecure) {
        parent::__construct();
        $this->dwState = STATE_DISCONNECTED;
        $this->dwBytesLeft = -1;
        $this->szHttpData = "";
        $this->szHost = $szHost;
        $this->wPort = $wPort;
        $this->bSecure = $bSecure;

        MainLoop::GetInstance()->RegisterObject($this);
    }

    function Sockets() {
        $aStreams = [];
        if ($this->hSocket != null) {
            array_push($aStreams, $this->hSocket);
        }
        return $aStreams;
    }

    function Onunblock($hSocket) {
        if ($this->dwState == STATE_HEADERS_RECEIVED && $this->dwBytesLeft != -1) {
            $abBuf = fread($this->hSocket, $this->dwBytesLeft);
        } else {
            $abBuf = fread($this->hSocket, 65536);
        }

        if ($abBuf === "" || $abBuf === false) {
            printf("[i] http socket closed\n");
            fclose($this->hSocket);
            $dwStateOnClose = $this->dwState;
            $dwBytesLeftOnClose = $this->dwBytesLeft;
            $this->dwState = STATE_DISCONNECTED;
            $this->dwBytesLeft = -1;
            $this->hSocket = null;

            if ($dwStateOnClose === STATE_HEADERS_RECEIVED && $dwBytesLeftOnClose == -1) {
                goto _process_body;
            } else if ($dwStateOnClose === STATE_HEADERS_SENT || $dwStateOnClose === STATE_HEADERS_RECEIVED) {
                MainLoop::GetInstance()->CancelTimer($this, "RequestTimeout", null);
                $this->Signal("http_error", "connection reset by peer");
                $this->Teardown();
            }
            return;
        }

        $this->szHttpData .= $abBuf;
        if ($this->dwBytesLeft != -1) {
            $this->dwBytesLeft -= strlen($abBuf);
            if ($this->dwBytesLeft < 0) {
                $this->dwBytesLeft = 0;
            }
        }
        if ($this->dwState == STATE_HEADERS_SENT) {
            if (($dwPos = strpos($this->szHttpData, "\r\n\r\n")) !== false) {
                $szHeaders = substr($this->szHttpData, 0, $dwPos);
                if (preg_match('/^Content-Length: ([0-9]+)\s*$/im', $szHeaders, $aMatchContentLength)) {
                    $dwContentLength = intval($aMatchContentLength[1]);
                    $this->dwBytesLeft = $dwContentLength - strlen($this->szHttpData) + $dwPos + 4;
                } else {
                    $this->dwBytesLeft = -1;
                }
                $this->dwState = STATE_HEADERS_RECEIVED;
            }
        }
        if ($this->dwState == STATE_HEADERS_RECEIVED) {
            if ($this->dwBytesLeft == 0) {
_process_body:
                $dwPos = strpos($this->szHttpData, "\r\n\r\n");
                if ($this->dwState != STATE_DISCONNECTED) {
                    $this->dwState = STATE_CONNECTED;
                }
                MainLoop::GetInstance()->CancelTimer($this, "RequestTimeout", null);
                $szBody = substr($this->szHttpData, $dwPos + 4);
                $this->szHttpData = "";
                $this->dwBytesLeft = -1;
                $this->Signal("http_response", $szBody);
            }
        }
    }

    function RequestTimeout() {
        $this->Signal("http_error", "request timeout");
        $this->Teardown();
    }

    function SendRequest($szUri, $dwTimeout, $aExtraHeaders = []) {
        if ($this->dwState != STATE_CONNECTED) {
            $this->hSocket = @fsockopen(($this->bSecure ? "tls://" : "") . $this->szHost, $this->wPort);
            if (!is_resource($this->hSocket)) {
                $this->hSocket = null;
                $this->dwState = STATE_DISCONNECTED;
                $this->Signal("http_error", "unable to connect to " . $this->szHost);
                $this->Teardown();
                return;
            }
            $this->dwState = STATE_CONNECTED;
        }

        $szHeaders = "GET " . $szUri . " HTTP/1.0\r\n";
        $szHeaders .= "Host: " . $this->szHost . "\r\n";
        $szHeaders .= "Connection: keep-alive\r\n";
        $szHeaders .= "Keep-Alive: 300\r\n";
        foreach ($aExtraHeaders as $szHeader) {
            $szHeaders .= $szHeader . "\r\n";
        }
        $szHeaders .= "\r\n";

        fwrite($this->hSocket, $szHeaders);
        $this->dwState = STATE_HEADERS_SENT;
        $this->szHttpData = "";

        MainLoop::GetInstance()->RegisterTimer($this, "RequestTimeout", null, $dwTimeout);
    }

    function Teardown() {
        if ($this->hSocket !== null) {
            @fclose($this->hSocket);
            $this->hSocket = null;
        }
        $this->dwState = STATE_DISCONNECTED;
        $this->dwBytesLeft = -1;
        $this->szHttpData = "";
        $this->CancelAllSubscriptions();
        MainLoop::GetInstance()->CancelTimer($this, "RequestTimeout", null);
    }
}

?>