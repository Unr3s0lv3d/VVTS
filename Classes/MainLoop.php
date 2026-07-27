<?php

namespace VVTS\Classes;

require_once(dirname(__FILE__) . "/../autoload.php");

use \VVTS\Types\TimerEvent;

$g_oMainLoop = null;

class MainLoop {
    var $aObjects;
    var $bExit;
    var $ahUnblockSockets;
    var $aRegisteredTimers;

    static function GetInstance() {
        global $g_oMainLoop;
        if ($g_oMainLoop == null) {
            $g_oMainLoop = new MainLoop();
        }
        return $g_oMainLoop;
    }

    function __construct() {
        global $g_oMainLoop;

        $this->aObjects = [];
        $this->ahUnblockSockets = stream_socket_pair(AF_UNIX, SOCK_STREAM, 0);
        $this->aRegisteredTimers = [];
    }

    function RegisterObject($oUnblockable) {
        array_push($this->aObjects, $oUnblockable);
    }

    function RegisterTimer($oObject, $lpHandler, $lpArgument, $dwMillis) {
        $dwMillis = intval(microtime(1) * 1000) + $dwMillis;
        array_push($this->aRegisteredTimers, new TimerEvent($oObject, $lpHandler, $lpArgument, $dwMillis));
    }

    function CancelTimer($oObject, $lpHandler, $lpArgument) {
        foreach($this->aRegisteredTimers as $i => $oRegisteredTimer) {
            if (
                $oRegisteredTimer->oObject === $oObject &&
                $oRegisteredTimer->lpHandler === $lpHandler &&
                $oRegisteredTimer->lpArgument === $lpArgument
            ) {
                unset($this->aRegisteredTimers[$i]);
                break;
            }
        }
    }

    function GetSoonestTimer() {
        $dwSoonest = null;
        foreach($this->aRegisteredTimers as $oTimer) {
            if ($dwSoonest == null || $oTimer->dwTimestamp < $dwSoonest) {
                $dwSoonest = $oTimer->dwTimestamp;
            }
        }
        if ($dwSoonest != null) {
            $dwSoonest -= intval(microtime(true) * 1000);
        }
        return $dwSoonest < 0 ? 0 : $dwSoonest;
    }

    static function SignalHandler($dwSignal, $aSigInfo) {
        printf("[i] caught signal, interrupting MainLoop\n");
        MainLoop::GetInstance()->bExit = true;
        MainLoop::GetInstance()->Wake();
    }

    function Wake() {
        fwrite($this->ahUnblockSockets[0], "\x00");
    }

    function Loop() {
        pcntl_signal(SIGINT, "\\VVTS\\Classes\\MainLoop::SignalHandler");
        pcntl_signal(SIGTERM, "\\VVTS\\Classes\\MainLoop::SignalHandler");
        pcntl_async_signals(true);

        for(;;) {
            $aRead = [];
            $aWrite = [];
            $aExcept = [];

            array_push($aRead, $this->ahUnblockSockets[1]);
            foreach($this->aObjects as $oObject) {
                $aRead = array_merge($aRead, $oObject->Sockets());
            }

            $dwSoonestTimer = $this->GetSoonestTimer();

            $dwStatus = @stream_select(
                $aRead, $aWrite, $aExcept,
                $dwSoonestTimer === null ? null : intval($dwSoonestTimer / 1000),
                $dwSoonestTimer === null ? null : ($dwSoonestTimer % 1000) * 1000
            );

            if ($dwStatus !== false) {
                foreach($this->aObjects as $oObject) {
                    $aSockets = $oObject->Sockets();
                    foreach($aSockets as $hSocket) {
                        if (in_array($hSocket, $aRead, true)) {
                            if ($oObject->Onunblock($hSocket) === false) {
                                $this->bExit = true;
                            }
                        }
                    }
                }
            }

            $dwCurrentTime = intval(microtime(true) * 1000);

            foreach($this->aRegisteredTimers as $i => $oRegisteredTimer) {
                if ($oRegisteredTimer->dwTimestamp <= $dwCurrentTime) {
                    unset($this->aRegisteredTimers[$i]);
                    if ($oRegisteredTimer->oObject == NULL) {
                        if ($oRegisteredTimer->lpArgument == null) {
                            call_user_func($oRegisteredTimer->lpHandler);
                        } else {
                            call_user_func($oRegisteredTimer->lpHandler, $oRegisteredTimer->lpArgument);
                        }
                    } else {
                        if ($oRegisteredTimer->lpArgument == null) {
                            call_user_func([$oRegisteredTimer->oObject, $oRegisteredTimer->lpHandler]);
                        } else {
                            call_user_func([$oRegisteredTimer->oObject, $oRegisteredTimer->lpHandler], $oRegisteredTimer->lpArgument);
                        }
                    }
                }
            }

            if (in_array($this->ahUnblockSockets[1], $aRead, true)) {
                fread($this->ahUnblockSockets[1], 1);
            }

            if ($this->bExit) {
                break;
            }
        }

        foreach($this->aObjects as $oObject) {
            $oObject->Teardown();
        }
    }
}

?>