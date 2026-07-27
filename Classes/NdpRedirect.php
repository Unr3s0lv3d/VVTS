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

/**
 * NdpRedirect — stuurt ICMPv6 Redirect berichten naar verbonden clients.
 *
 * Werking:
 *   1. bring_up() start ndp_redirect.py als subprocess.
 *   2. Zodra SLAAC een nieuwe client meldt (slaac_renew), wordt de
 *      client automatisch doorgegeven aan het Python script.
 *   3. Het Python script stuurt periodiek Redirect paketten:
 *      "Voor bestemming X, gebruik de AP als next-hop."
 *
 * Gebruik in een VVTS script:
 *   ndp_redirect.add_target("2607:f8b0:4004:c08::8b")   # Google IPv6
 *   ndp_redirect.bring_up(@success, @error)
 */
class NdpRedirect extends Subscribable implements IUnblockable, IScriptOpaque {
    var $aTargets    = [];
    var $dwInterval  = null;        /* null = gebruik Python standaard (30s) */
    var $hProcess;
    var $hProcessStdin;
    var $hProcessStdout;
    var $hProcessStderr;
    var $aTransitions = [];

    function __construct() {
        parent::__construct();
        MainLoop::GetInstance()->RegisterObject($this);
    }

    /* ------------------------------------------------------------------ */
    /* MainLoop interface                                                   */
    /* ------------------------------------------------------------------ */

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
        /* Na Teardown() kunnen handles al gesloten zijn terwijl de MainLoop
           ze nog één keer aanbiedt. Goedaardig afvangen. */
        if (!is_resource($hSocket)) {
            return;
        }
        $szLine = fgets($hSocket, 1024);
        if ($szLine === "" || $szLine === false) {
            ScriptEngine::GetInstance()->SetErrstr("ndp_redirect process ended unexpectedly");
            $this->Teardown();
            $this->PerformTransition("error");
            return;
        }
        printf("ndp_redirect: %s", $szLine);

        if (strpos($szLine, "started") !== false) {
            printf("[i] ndp redirect up\n");

            /* Stuur geconfigureerde targets door naar het script */
            foreach ($this->aTargets as $szTarget) {
                $this->WriteCommand("target " . $szTarget);
            }
            if ($this->dwInterval !== null) {
                $this->WriteCommand("interval " . intval($this->dwInterval));
            }

            $this->PerformTransition("success");
        }
    }

    /* ------------------------------------------------------------------ */
    /* Lifecycle                                                            */
    /* ------------------------------------------------------------------ */

    function Teardown() {
        if ($this->hProcessStdin !== null) {
            fwrite($this->hProcessStdin, "quit\n");
            fclose($this->hProcessStdin);
            $this->hProcessStdin = null;
        }
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

        $this->CancelAllSubscriptions();
    }

    function PerformTransition($szWhich) {
        if (isset($this->aTransitions[$szWhich])) {
            $oTransition = $this->aTransitions[$szWhich];
            $this->aTransitions = [];
            ScriptEngine::GetInstance()->EnterState($oTransition);
        }
    }

    /* ------------------------------------------------------------------ */
    /* Helpers                                                              */
    /* ------------------------------------------------------------------ */

    private function WriteCommand($szCmd) {
        if ($this->hProcessStdin !== null) {
            fwrite($this->hProcessStdin, $szCmd . "\n");
            fflush($this->hProcessStdin);
        }
    }

    /**
     * Haal het link-local adres op van de AP-interface (fe80::...).
     * Nodig als bronAdres voor de Redirect paketten.
     */
    private function GetApLinkLocal($szInterface) {
        $szOutput = shell_exec("ip -6 addr show dev " . escapeshellarg($szInterface) . " scope link 2>/dev/null");
        if (preg_match('/inet6\s+(fe80::[^\s\/]+)/i', $szOutput, $aMatch)) {
            return $aMatch[1];
        }
        return null;
    }

    /* ------------------------------------------------------------------ */
    /* Callback: nieuwe SLAAC client verbonden                              */
    /* ------------------------------------------------------------------ */

    function OnSlaacRenew($szClientIpv6) {
        $szClientIpv6 = trim($szClientIpv6);
        if (MiscNet::Ipv6StringToBinary($szClientIpv6) === false) {
            printf("[-] ndp_redirect: ignoring invalid client address: %s\n", $szClientIpv6);
            return;
        }

        /* NDP Redirect pakketten moeten naar het link-local adres van de client.
           Als radvd een globaal unicast adres doorgeeft, zoek dan het bijbehorende
           link-local op via de neighbor table van de AP-interface. */
        if (strncasecmp($szClientIpv6, "fe80:", 5) !== 0) {
            $szLinkLocal = $this->LookupLinkLocal($szClientIpv6);
            if ($szLinkLocal === null) {
                printf("[i] ndp_redirect: no link-local found for %s, skipping\n", $szClientIpv6);
                return;
            }
            printf("[i] ndp_redirect: resolved %s -> %s\n", $szClientIpv6, $szLinkLocal);
            $szClientIpv6 = $szLinkLocal;
        }

        printf("[i] ndp_redirect: new client %s\n", $szClientIpv6);
        $this->WriteCommand("client " . $szClientIpv6);
    }

    /**
     * Zoek het link-local adres op dat bij een globaal SLAAC-adres hoort,
     * via de neighbor table van de AP-interface.
     */
    private function LookupLinkLocal($szGlobalAddr) {
        $oAp = AccessPoint::GetInstance();
        if ($oAp->szApInterface === null) {
            return null;
        }

        /* Haal MAC op die bij het globale adres hoort */
        $szNeigh = shell_exec("ip -6 neigh show dev " . escapeshellarg($oAp->szApInterface) . " 2>/dev/null");
        if ($szNeigh === null) {
            return null;
        }

        $szMac = null;
        foreach (explode("\n", $szNeigh) as $szLine) {
            if (stripos($szLine, $szGlobalAddr) !== false &&
                preg_match('/lladdr\s+([0-9a-f:]{17})/i', $szLine, $aMatch)) {
                $szMac = strtolower($aMatch[1]);
                break;
            }
        }

        if ($szMac === null) {
            return null;
        }

        /* Zoek link-local adres met hetzelfde MAC */
        foreach (explode("\n", $szNeigh) as $szLine) {
            if (stripos($szLine, "fe80:") === 0 &&
                stripos($szLine, $szMac) !== false &&
                preg_match('/^(fe80:[^\s]+)/i', $szLine, $aMatchAddr)) {
                $szLinkLocal = $aMatchAddr[1];
                if (MiscNet::Ipv6StringToBinary($szLinkLocal) !== false) {
                    return $szLinkLocal;
                }
            }
        }

        return null;
    }

    /* ------------------------------------------------------------------ */
    /* Script engine interface                                              */
    /* ------------------------------------------------------------------ */

    function StateMachineInvoke_add_target(...$aArguments) {
        if (count($aArguments) !== 1) {
            throw new ScriptInvokeError("add_target requires one argument");
        } else if (!($aArguments[0] instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("add_target requires a string argument");
        }

        $szTarget = trim($aArguments[0]->szLiteral);
        if (MiscNet::Ipv6StringToBinary($szTarget) === false) {
            throw new ScriptInvokeError("add_target: invalid IPv6 address: " . $szTarget);
        }

        array_push($this->aTargets, $szTarget);

        /* Als het script al draait, stuur target direct door */
        if ($this->hProcessStdin !== null) {
            $this->WriteCommand("target " . $szTarget);
        }

        return new ScriptVoid();
    }

    function StateMachineSet_interval($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("interval must be of type string");
        }
        $dwInterval = intval($oValue->szLiteral);
        if ($dwInterval <= 0) {
            throw new ScriptInvokeError("interval must be a positive number of seconds");
        }
        $this->dwInterval = $dwInterval;

        if ($this->hProcessStdin !== null) {
            $this->WriteCommand("interval " . $dwInterval);
        }
    }

    function StateMachineInvoke_add_client(...$aArguments) {
        if (count($aArguments) !== 1) {
            throw new ScriptInvokeError("add_client requires one argument");
        } else if (!($aArguments[0] instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("add_client requires a string argument");
        }

        $szClient = trim($aArguments[0]->szLiteral);
        if (MiscNet::Ipv6StringToBinary($szClient) === false) {
            throw new ScriptInvokeError("add_client: invalid IPv6 address: " . $szClient);
        }

        $this->WriteCommand("client " . $szClient);
        return new ScriptVoid();
    }

    function StateMachineInvoke_flush(...$aArguments) {
        if (count($aArguments) !== 0) {
            throw new ScriptInvokeError("flush requires no arguments");
        }
        $this->WriteCommand("flush");
        return new ScriptVoid();
    }

    function StateMachineInvoke_bring_up(...$aArguments) {
        if (count($aArguments) !== 2) {
            throw new ScriptInvokeError("bring_up requires a success state and an error state");
        } else if (!($aArguments[0] instanceof ScriptState) || !($aArguments[1] instanceof ScriptState)) {
            throw new ScriptInvokeError("bring_up requires two state arguments");
        }

        $oAp = AccessPoint::GetInstance();
        if ($oAp->szApInterface === null) {
            throw new ScriptInvokeError("ndp_redirect: access point must be up before calling bring_up()");
        }

        /* Haal link-local adres op van de AP interface */
        $szApLinkLocal = $this->GetApLinkLocal($oAp->szApInterface);
        if ($szApLinkLocal === null) {
            ScriptEngine::GetInstance()->SetErrstr("ndp_redirect: no link-local address on " . $oAp->szApInterface . " — is slaac_enable set?");
            $this->PerformTransition("error");
            return new ScriptVoid();
        }

        $this->aTransitions["success"] = ScriptEngine::GetInstance()->RegisterStateTransition($aArguments[0]);
        $this->aTransitions["error"]   = ScriptEngine::GetInstance()->RegisterStateTransition($aArguments[1]);

        /* Automatisch luisteren naar nieuwe SLAAC clients */
        if ($oAp->oSlaac !== null) {
            $oAp->oSlaac->Subscribe("slaac_renew", $this, "OnSlaacRenew", null, false);
        }

        $szScript = dirname(__FILE__) . "/../src/ndp_redirect";
        $aSpec = [
            0 => ["pipe", "r"],   /* stdin  — PHP schrijft commando's hiernaar */
            1 => ["pipe", "w"],   /* stdout — binary rapporteert status */
            2 => ["pipe", "w"],   /* stderr */
        ];

        $this->hProcess = proc_open(
            "exec " .
                escapeshellarg($szScript) . " " .
                escapeshellarg($oAp->szApInterface) . " " .
                escapeshellarg($szApLinkLocal),
            $aSpec,
            $aPipes
        );

        if ($this->hProcess === false) {
            ScriptEngine::GetInstance()->SetErrstr("ndp_redirect: failed to start python3 script");
            $this->PerformTransition("error");
            return new ScriptVoid();
        }

        $this->hProcessStdin  = $aPipes[0];
        $this->hProcessStdout = $aPipes[1];
        $this->hProcessStderr = $aPipes[2];

        return new ScriptVoid();
    }
}

?>
