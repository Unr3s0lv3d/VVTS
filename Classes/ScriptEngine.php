<?php

namespace VVTS\Classes;

require_once dirname(__FILE__) . "/../autoload.php";

use \VVTS\Classes\MainLoop;
use \VVTS\Classes\MiscNet;
use \VVTS\Classes\AccessPoint;
use \VVTS\Classes\TrafficMonitor;
use \VVTS\Classes\SslStrip;
use \VVTS\Classes\NdpRedirect;
use \VVTS\Classes\RemoteProxy;
use \VVTS\Types\ScriptVoid;
use \VVTS\Types\ScriptInvokeError;
use \VVTS\Types\ScriptStringLiteral;
use \VVTS\Types\ScriptStateTransition;
use \VVTS\Types\ScriptAssignment;
use \VVTS\Types\ScriptInvokeBuiltin;
use \VVTS\Types\ScriptLabel;
use \VVTS\Types\ScriptState;
use \VVTS\Interfaces\IScriptOpaque;
use \Exception;

$g_oScriptEngine = null;

class ScriptEngine {
    var $oScript;
    var $aStatesByLabel;
    var $oInitState;
    var $aVariables;
    var $aRegisteredFunctions;
    var $oCurrentState;
    var $aRegisteredStateTransitions;
    var $bIsTransitioning;
    var $aPostponedTransitions;

    function __construct() {
        $this->aRegisteredFunctions = [];
        $this->bIsTransitioning = false;
        $this->aPostponedTransitions = [];
        $this->RegisterBuiltin("exit", "\\VVTS\\Classes\\ScriptEngine::StateMachineInvoke_exit");
        $this->RegisterBuiltin("print", "\\VVTS\\Classes\\ScriptEngine::StateMachineInvoke_print");
        $this->RegisterBuiltin("concat", "\\VVTS\\Classes\\ScriptEngine::StateMachineInvoke_concat");
        $this->RegisterBuiltin("miscnet", function() {
            return MiscNet::GetInstance();
        });
        $this->RegisterBuiltin("accesspoint", function() {
            return AccessPoint::GetInstance();
        });
        $this->RegisterBuiltin("trafficmonitor", function() {
            return new TrafficMonitor();
        });
        $this->RegisterBuiltin("sslstrip", function() {
            return new SslStrip();
        });
        $this->RegisterBuiltin("ndp_redirect", function() {
            return new NdpRedirect();
        });
        $this->RegisterBuiltin("remote_proxy", function() {
            return new RemoteProxy();
        });
    }

    static function StateMachineInvoke_print(...$aArguments) {
        foreach($aArguments as $oArgument) {
            if ($oArgument instanceof ScriptStringLiteral) {
                printf("%s", $oArgument->szLiteral);
            } else if ($oArgument instanceof IScriptOpaque) {
                if (method_exists($oArgument, "ToString")) {
                    printf("%s", $oArgument->ToString());
                } else {
                    printf("[%s]", get_class($oArgument));
                }
            } else if ($oArgument instanceof ScriptVoid) {
                printf("[void]");
            } else if ($oArgument instanceof ScriptState) {
                printf("[state %s]", $oArgument->oLabel->ToString());
            }
        }
        printf("\n");
        return new ScriptVoid();
    }

    static function StateMachineInvoke_exit(...$aArguments) {
        self::StateMachineInvoke_print(...$aArguments);
        MainLoop::GetInstance()->bExit = true;
        MainLoop::GetInstance()->Wake();
        return new ScriptVoid();
    }

    static function StateMachineInvoke_concat(...$aArguments) {
        $szResult = "";
        foreach($aArguments as $oArgument) {
            if (!($oArgument instanceof ScriptStringLiteral)) {
                throw new ScriptInvokeError("concat() requires all parameters to be strings");
            }
            $szResult .= $oArgument->szLiteral;
        }

        return new ScriptStringLiteral($szResult);
    }

    static function GetInstance() {
        global $g_oScriptEngine;

        if ($g_oScriptEngine === null) {
            $g_oScriptEngine = new ScriptEngine();
        }
        return $g_oScriptEngine;
    }

    function RegisterScript($oScript) {
        $this->oScript = $oScript;
        $this->aStatesByLabel = [];
        $this->oInitState = null;
        $this->aVariables = [];
        $this->aRegisteredStateTransitions = [];

        foreach($this->oScript->aStates as $oState) {
            $this->aStatesByLabel[$oState->oLabel->szLabel] = $oState;
            if ($oState->bIsInitState) {
                $this->oInitState = $oState;
            }
        }
    }

    function RegisterBuiltin($szFunctionLabel, $lpConstructor) {
        $this->aRegisteredFunctions[$szFunctionLabel] = $lpConstructor;
    }

    function EnterInitState() {
        $oTransition = $this->RegisterStateTransition($this->oInitState);
        $this->EnterState($oTransition);
    }

    function EvalValue($oValue) {
        if (
            $oValue instanceof ScriptStringLiteral ||
            $oValue instanceof IScriptOpaque ||
            $oValue instanceof ScriptVoid ||
            $oValue instanceof ScriptState
        ) {
            $oEvaluated = $oValue;
        } else if ($oValue instanceof ScriptLabel) {
            if ($oValue->szVariable != null) {
                $szVariable = $oValue->szVariable;
                $szMember = $oValue->szLabel;

                if (isset($this->aVariables[$szVariable])) {
                    if ($this->aVariables[$szVariable] instanceof IScriptOpaque) {
                        if (method_exists($this->aVariables[$szVariable], "StateMachineGet_" . $szMember)) {
                            $oEvaluated = call_user_func([$this->aVariables[$szVariable], "StateMachineGet_" . $szMember]);
                            if (!(
                                $oEvaluated instanceof IScriptOpaque ||
                                $oEvaluated instanceof ScriptStringLiteral ||
                                $oEvaluated instanceof ScriptState ||
                                $oEvaluated instanceof ScriptVoid
                            )) {
                                throw new ScriptInvokeError("StateMachineGet_" . $szMember . " returned invalid type");
                            }
                            goto _done_read;
                        } else {
                            throw new ScriptInvokeError("Property " . $szMember . " of object " . $szVariable . " does not exist");
                        }
                    } else {
                        throw new ScriptInvokeError("Cannot read property " . $szMember . " of builtin class " . get_class($this->aVariables[$szVariable]));
                    }
                } else {
                    throw new ScriptInvokeError("Variable " . $szVariable . " not defined");
                }
            }
            if (isset($this->aVariables[$oValue->szLabel])) {
                $oEvaluated = $this->aVariables[$oValue->szLabel];
            } else if (isset($this->aStatesByLabel[$oValue->szLabel])) {
                $oEvaluated = $this->aStatesByLabel[$oValue->szLabel];
            } else {
                throw new ScriptInvokeError("Variable " . $oValue->szLabel . " not defined");
            }
_done_read:
        } else if ($oValue instanceof ScriptInvokeBuiltin) {

            if ($oValue->oLabel->szVariable !== null) {
                $szVariable = $oValue->oLabel->szVariable;
                $szMethod = $oValue->oLabel->szLabel;

                if (isset($this->aVariables[$szVariable])) {
                    if ($this->aVariables[$szVariable] instanceof IScriptOpaque) {
                        if (method_exists($this->aVariables[$szVariable], "StateMachineInvoke_" . $szMethod)) {
                            $aArguments = [];
                            foreach($oValue->aArguments as $oArgument) {
                                array_push($aArguments, $this->EvalValue($oArgument));
                            }
                            $oEvaluated = call_user_func(
                                [$this->aVariables[$szVariable], "StateMachineInvoke_" . $szMethod],
                                ...$aArguments
                            );
                            goto _done_invoke;
                        } else {
                            throw new ScriptInvokeError("Method " . $szMethod . " on object " . $szVariable . " does not exist");
                        }
                    } else {
                        throw new ScriptInvokeError("Cannot invoke method " . $szMethod . " of builtin class " . get_class($this->aVariables[$szVariable]));
                    }
                } else {
                    throw new ScriptInvokeError("Variable " . $szVariable . " not defined");
                }
            }

            if (!isset($this->aRegisteredFunctions[$oValue->oLabel->szLabel])) {
                throw new ScriptInvokeError("Function " . $oValue->oLabel->szLabel . " not defined");
            }

            $aArguments = [];
            foreach($oValue->aArguments as $oArgument) {
                array_push($aArguments, $this->EvalValue($oArgument));
            }
            $oEvaluated = call_user_func($this->aRegisteredFunctions[$oValue->oLabel->szLabel], ...$aArguments);
_done_invoke:
            if (!(
                $oEvaluated instanceof IScriptOpaque ||
                $oEvaluated instanceof ScriptStringLiteral ||
                $oEvaluated instanceof ScriptState ||
                $oEvaluated instanceof ScriptVoid
            )) {
                throw new ScriptInvokeError($oValue->oLabel->ToString() . " returned invalid type");
            }

        } else {
            throw new ScriptInvokeError("Unknown type, unable to evaluate");
        }
        return $oEvaluated;
    }

    function EvalStatement($oStatement) {
        if ($oStatement instanceof ScriptAssignment) {
            $oRvalue = $this->EvalValue($oStatement->oRvalue);

            if ($oRvalue instanceof ScriptVoid) {
                throw new ScriptInvokeError("Cannot assign void type to " . $oStatement->oLvalue->ToString());
            }

            if ($oStatement->oLvalue->szVariable != null) {
                $szVariable = $oStatement->oLvalue->szVariable;
                $szMember = $oStatement->oLvalue->szLabel;

                if (isset($this->aVariables[$szVariable])) {
                    if ($this->aVariables[$szVariable] instanceof IScriptOpaque) {
                        if (method_exists($this->aVariables[$szVariable], "StateMachineSet_" . $szMember)) {
                            call_user_func([$this->aVariables[$szVariable], "StateMachineSet_" . $szMember], $oRvalue);
                            goto _done_write;
                        } else {
                            throw new ScriptInvokeError("Property " . $szMember . " of object " . $szVariable . " does not exist");
                        }
                    } else {
                        throw new ScriptInvokeError("Cannot write property " . $szMember . " of builtin class " . get_class($this->aVariables[$szVariable]));
                    }
                } else {
                    throw new ScriptInvokeError("Variable " . $szVariable . " not defined");
                }
            }

            if (isset($this->aStatesByLabel[$oStatement->oLvalue->szLabel])) {
                throw new ScriptInvokeError("Cannot set value to state label " . $oStatement->oLvalue->szLabel);
            }
            $this->aVariables[$oStatement->oLvalue->szLabel] = $oRvalue;
_done_write:
        } else {
            $this->EvalValue($oStatement);
        }
    }

    function EnterState($oStateTransition) {
        if ($this->bIsTransitioning) {
            array_push($this->aPostponedTransitions, $oStateTransition);
            return;
        }

        $this->bIsTransitioning = true;

        if ($this->oCurrentState !== null) {
            if (!in_array($oStateTransition, $this->aRegisteredStateTransitions, true)) {
                printf("[-] Illegal state transition: %s -> %s\n",
                    $this->oCurrentState->oLabel->ToString(),
                    $oStateTransition->oDestinationState->oLabel->ToString()
                );
                MainLoop::GetInstance()->bExit = true;
                MainLoop::GetInstance()->Wake();
                return;
            }
        }
        $this->aRegisteredStateTransitions = [];
        $this->oCurrentState = $oStateTransition->oDestinationState;

        printf("[i] Entering state: \"%s\"\n", $this->oCurrentState->oLabel->ToString());
        foreach($this->oCurrentState->aStatements as $oStatement) {
            try {
                $this->EvalStatement($oStatement);
            } catch (Exception $e) {
                printf("[-] caught exception: %s\n", $e->getMessage());
                MainLoop::GetInstance()->bExit = true;
                MainLoop::GetInstance()->Wake();
                return;
            }
        }

        $this->bIsTransitioning = false;
        while (count($this->aPostponedTransitions) != 0) {
            $oPostponed = $this->aPostponedTransitions[0];
            array_splice($this->aPostponedTransitions, 1);
            $this->EnterState($oPostponed);
            if (MainLoop::GetInstance()->bExit) {
                break;
            }
        }
    }

    function RegisterStateTransition($oState) {
        $oTransition = new ScriptStateTransition($oState);
        array_push($this->aRegisteredStateTransitions, $oTransition);
        return $oTransition;
    }

    function SetErrstr($szErrstr) {
        $this->aVariables["errstr"] = new ScriptStringLiteral($szErrstr);
    }

    function SetString($szName, $szValue) {
        $this->aVariables[$szName] = new ScriptStringLiteral($szValue);
    }
}

?>