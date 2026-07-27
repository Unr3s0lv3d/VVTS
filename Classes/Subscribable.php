<?php

namespace VVTS\Classes;

require_once(dirname(__FILE__) . "/../autoload.php");

use \VVTS\Types\SignalSubscriber;

class Subscribable {
    var $aSubscribers;

    function __construct () {
        $this->aSubscribers = [];
    }

    function Subscribe($szSignal, $oCallbackObj, $szCallbackFunction, $lpCallbackArgument, $bOneShot) {
        array_push($this->aSubscribers, new SignalSubscriber($szSignal, $oCallbackObj, $szCallbackFunction, $lpCallbackArgument, $bOneShot));
    }

    function CancelAllSubscriptions() {
        $this->aSubscribers = [];
    }

    function Signal($szSignal, ...$aArguments) {
        foreach($this->aSubscribers as $i => $oSubscriber) {
            if ($oSubscriber->szSignal === $szSignal) {
                if ($oSubscriber->oCallbackObj == NULL) {
                    if ($oSubscriber->lpCallbackArgument == null) {
                        call_user_func($oSubscriber->szCallbackFunction, ...$aArguments);
                    } else {
                        call_user_func($oSubscriber->szCallbackFunction, $oSubscriber->lpCallbackArgument, ...$aArguments);
                    }
                } else {
                    if ($oSubscriber->lpCallbackArgument == null) {
                        call_user_func([$oSubscriber->oCallbackObj, $oSubscriber->szCallbackFunction], ...$aArguments);
                    } else {
                        call_user_func([$oSubscriber->oCallbackObj, $oSubscriber->szCallbackFunction], $oSubscriber->lpCallbackArgument, ...$aArguments);
                    }
                }

                if ($oSubscriber->bOneShot) {
                    unset($this->aSubscribers[$i]);
                }
            }
        }
    }
}

?>