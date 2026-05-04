<?php

namespace VVTS\Classes;

require_once(dirname(__FILE__) . "/../autoload.php");

use \VVTS\Classes\MainLoop;
use \VVTS\Classes\MiscNet;
use \VVTS\Classes\ScriptEngine;
use \VVTS\Classes\HostApd;
use \VVTS\Classes\ArpResponder;
use \VVTS\Classes\DhcpServer;
use \VVTS\Classes\SlaacAdvertiser;
use \VVTS\Classes\Nat64;
use \VVTS\Classes\DnsMitm;
use \VVTS\Classes\WpadServer;
use \VVTS\Classes\CaptivePortalServer;
use \VVTS\Types\PerClientRoute;
use \VVTS\Types\RouteIpv6;
use \VVTS\Types\ScriptInvokeError;
use \VVTS\Types\ScriptState;
use \VVTS\Types\ScriptStringLiteral;
use \VVTS\Types\ScriptVoid;
use \VVTS\Types\StaticRoute;
use \VVTS\Types\StaticIpv6Route;
use \VVTS\Types\InterfaceInfo;
use \VVTS\Interfaces\IUnblockable;
use \VVTS\Interfaces\IScriptOpaque;

$g_oAccessPoint = null;

class AccessPoint implements IUnblockable, IScriptOpaque {
    var $oHostApd;
    var $oDhcp4;
    var $oSlaac;
    var $oNat64;
    var $oDnsMitm;
    var $oArpResponder;
    var $oWpadServer;
    var $oCaptivePortalServer;
    var $szWifiInterface;
    var $szWifiDriver;
    var $szWifiSsid;
    var $szWifiPassphrase;
    var $dwWifiChannel;

    var $szApInterface;
    var $dwIpv4Address;
    var $dwIpv4Netmask;
    var $abIpv6Address;
    var $dwIpv6PrefixLen;

    var $bDhcp4Enable;
    var $dwDhcp4Dns;
    var $dwDhcp4Router;
    var $dwDhcp4Avoid;
    var $dwDhcp4LeaseTime;
    var $szDhcp4Domain;
    var $aDhcp4StaticRoutes;
    var $dwDhcp4Netmask;
    var $dwDhcp4StaticRouteOption;

    var $bSlaacEnable;
    var $abSlaacDns;
    var $dwSlaacLifetime;
    var $szSlaacDomain;
    var $aSlaacStaticRoutes;
    var $aabSlaacNeighbors;

    var $szDhcp4WpadProxy;
    var $szDhcp4WpadDirect;
    var $szDhcp4WpadProxyHosts;
    var $szDhcp4WpadUrl;
    var $szCaptivePortalPage;
    var $szCaptivePortalRedirect;
    var $szCaptivePortalMode;
    var $szDhcp4CaptivePortalUri;
    var $bRouteToDefault;
    var $bNat64Enable;
    var $bDnsEnable;
    var $aDnsOverridesA;
    var $aDnsOverridesAAAA;
    var $aPerClientRoutes;
    var $aBacklog;
    var $aTransitions;

    function __construct() {
        $this->aBacklog = [];
        $this->aDnsOverridesA = [];
        $this->aDnsOverridesAAAA = [];
        $this->aPerClientRoutes = [];
        $this->aDhcp4StaticRoutes = [];
        $this->aSlaacStaticRoutes = [];
        $this->aabSlaacNeighbors = [];
        $this->aTransitions = [];
        $this->dwDhcp4StaticRouteOption = 121;

        MainLoop::GetInstance()->RegisterObject($this);
    }

    static function GetInstance() {
        global $g_oAccessPoint;
        if ($g_oAccessPoint == null) {
            $g_oAccessPoint = new AccessPoint();
        }
        return $g_oAccessPoint;
    }

    function Sockets() {
        return [];
    }

    function Onunblock($hSocket) { }

    function Teardown() {
        // printf("accesspoint::Teardown()\n");
        if ($this->oDnsMitm != null) { $this->oDnsMitm->Teardown(); $this->oDnsMitm = null; }
        if ($this->oArpResponder != null) { $this->oArpResponder->Teardown(); $this->oArpResponder = null; }
        if ($this->oWpadServer != null) { $this->oWpadServer->Teardown(); $this->oWpadServer = null; }
        if ($this->oCaptivePortalServer != null) { $this->oCaptivePortalServer->Teardown(); $this->oCaptivePortalServer = null; }
        if ($this->oDhcp4 != null) { $this->oDhcp4->Teardown(); $this->oDhcp4 = null; }
        if ($this->oSlaac != null) { $this->oSlaac->Teardown(); $this->oSlaac = null; }
        if ($this->oNat64 != null) { $this->oNat64->Teardown(); $this->oNat64 = null; }
        if ($this->oHostApd != null) { $this->oHostApd->Teardown(); $this->oHostApd = null; }

        foreach($this->aBacklog as $szBacklog) {
            shell_exec($szBacklog);
        }
        $this->aBacklog = [];

        foreach($this->aPerClientRoutes as $oPerClientRoute) {
            if ($oPerClientRoute->dwIpv4Address !== false) {
                MiscNet::DelRoute($oPerClientRoute->dwIpv4Address, false);
            }
            if ($oPerClientRoute->abIpv6Address !== false) {
                MiscNet::DelRouteIpv6($oPerClientRoute->abIpv6Address, false);
            }
        }
        $this->aPerClientRoutes = [];
        $this->aabSlaacNeighbors = [];
    }

    function PerformTransition($szWhich) {
        if (isset($this->aTransitions[$szWhich])) {
            $oTransition = $this->aTransitions[$szWhich];
            $this->aTransitions = [];
            ScriptEngine::GetInstance()->EnterState($oTransition);
        }
    }

    function Stage1_OnHostApUp() {
        printf("[.] Stage1_OnHostApUp\n");
        $this->szApInterface = $this->oHostApd->GetApInterface();
        if ($this->dwIpv4Address !== null) {
            $dwIpv4Netmask = ($this->dwIpv4Netmask === null) ? MiscNet::Ipv4StringToDword("255.255.255.0") : $this->dwIpv4Netmask;

            $szErrstr = shell_exec(
                "ifconfig " .
                    escapeshellarg($this->szApInterface) . " ".
                    escapeshellarg(MiscNet::DwordToIpv4String($this->dwIpv4Address)) . " ".
                    "netmask " . escapeshellarg(MiscNet::DwordToIpv4String($dwIpv4Netmask)) . " 2>&1"
            );

            if ($szErrstr !== "" && $szErrstr !== null) {
                ScriptEngine::GetInstance()->SetErrstr("Error configuring interface " . $this->szApInterface);
                goto _error;
            }

            if ($this->szDhcp4WpadUrl === null && $this->szDhcp4WpadProxy !== null) {
                $this->oWpadServer = new WpadServer();
                $this->oWpadServer->szBindAddr = MiscNet::DwordToIpv4String($this->dwIpv4Address);
                $this->oWpadServer->szProxyAddr = $this->szDhcp4WpadProxy;
                if ($this->szDhcp4WpadDirect !== null) {
                    foreach(array_filter(explode(';', $this->szDhcp4WpadDirect)) as $szHost) {
                        array_push($this->oWpadServer->aDirectHosts, trim($szHost));
                    }
                }
                if ($this->szDhcp4WpadProxyHosts !== null) {
                    foreach(array_filter(explode(';', $this->szDhcp4WpadProxyHosts)) as $szEntry) {
                        $aParts = explode('=', trim($szEntry), 2);
                        if (count($aParts) === 2) {
                            $this->oWpadServer->aProxyHosts[trim($aParts[0])] = trim($aParts[1]);
                        }
                    }
                }
                $this->oWpadServer->Subscribe("wpad_up", $this, "Stage1b_OnWpadUp", null, true);
                $this->oWpadServer->Subscribe("wpad_err", $this, "Stage1b_OnWpadErr", null, true);
                $this->oWpadServer->BringUp();
                return;
            }
        }

        return $this->Stage1b_OnWpadUp();

_error:
        $this->Teardown();
        return $this->PerformTransition("error");
    }

    function Stage1b_OnWpadUp() {
        printf("[.] Stage1b_OnWpadUp\n");

        if ($this->szCaptivePortalMode !== null && $this->dwIpv4Address !== null) {
            $this->oCaptivePortalServer = new CaptivePortalServer();
            $this->oCaptivePortalServer->szBindAddr = MiscNet::DwordToIpv4String($this->dwIpv4Address);
            $this->oCaptivePortalServer->szPortalPage = $this->szCaptivePortalPage;
            $this->oCaptivePortalServer->szRedirectUrl = $this->szCaptivePortalRedirect;
            $this->oCaptivePortalServer->szExternalPortalUrl = $this->szDhcp4CaptivePortalUri;
            $this->oCaptivePortalServer->Subscribe("portal_up", $this, "Stage1c_OnPortalUp", null, true);
            $this->oCaptivePortalServer->Subscribe("portal_err", $this, "Stage1c_OnPortalErr", null, true);
            $this->oCaptivePortalServer->Subscribe("client_authorized", $this, "OnClientAuthorized", null, false);
            $this->oCaptivePortalServer->BringUp();
            return;
        }

        return $this->Stage1c_OnPortalUp();
    }

    function Stage1c_OnPortalUp() {
        printf("[.] Stage1c_OnPortalUp\n");

        if ($this->szCaptivePortalMode === "dns_all" && $this->szApInterface !== null) {
            $szIface = $this->szApInterface;
            shell_exec("iptables -N VVTS_PORTAL 2>/dev/null");
            shell_exec("iptables -I FORWARD -i " . escapeshellarg($szIface) . " -j VVTS_PORTAL");
            shell_exec("iptables -I INPUT -i " . escapeshellarg($szIface) . " -j VVTS_PORTAL");
            shell_exec("iptables -A VVTS_PORTAL -p udp --dport 67 -j ACCEPT");
            shell_exec("iptables -A VVTS_PORTAL -p udp --dport 53 -j ACCEPT");
            shell_exec("iptables -A VVTS_PORTAL -p tcp --dport 80 -j ACCEPT");
            shell_exec("iptables -A VVTS_PORTAL -j DROP");

            array_push($this->aBacklog, "iptables -D FORWARD -i " . escapeshellarg($szIface) . " -j VVTS_PORTAL 2>/dev/null");
            array_push($this->aBacklog, "iptables -D INPUT -i " . escapeshellarg($szIface) . " -j VVTS_PORTAL 2>/dev/null");
            array_push($this->aBacklog, "iptables -F VVTS_PORTAL 2>/dev/null");
            array_push($this->aBacklog, "iptables -X VVTS_PORTAL 2>/dev/null");
        }

        if ($this->bDhcp4Enable) {
            $this->oDhcp4 = new DhcpServer();
            $this->oDhcp4->szInterface = $this->szApInterface;
            $this->oDhcp4->dwDns = $this->dwDhcp4Dns;
            $this->oDhcp4->dwRouter = $this->dwDhcp4Router;
            $this->oDhcp4->dwAvoid = $this->dwDhcp4Avoid;
            $this->oDhcp4->dwLeaseTime = $this->dwDhcp4LeaseTime;
            $this->oDhcp4->szDomain = $this->szDhcp4Domain;
            foreach($this->aDhcp4StaticRoutes as $oRoute) {
                $this->oDhcp4->SetStaticRoute($oRoute->dwAddress, $oRoute->dwNetmask, $oRoute->dwGateway);
            }
            $this->oDhcp4->dwNetmask = $this->dwDhcp4Netmask;
            $this->oDhcp4->dwStaticRouteOption = $this->dwDhcp4StaticRouteOption;
            if ($this->szDhcp4WpadUrl !== null) {
                $this->oDhcp4->szWpadUrl = $this->szDhcp4WpadUrl;
            } else if ($this->szDhcp4WpadProxy !== null) {
                $this->oDhcp4->szWpadUrl = "http://" . MiscNet::DwordToIpv4String($this->dwIpv4Address) . "/wpad.dat";
            }
            if ($this->szDhcp4CaptivePortalUri !== null) {
                /* Externe captive portal API URL — wordt direct als opt 114 verstuurd.
                 * De externe server handelt zowel RFC 8908 JSON als de HTML portal pagina af. */
                $this->oDhcp4->szCaptivePortalUri = $this->szDhcp4CaptivePortalUri;
            } else if ($this->szCaptivePortalMode !== null && $this->dwIpv4Address !== null) {
                /* advertise local API endpoint via opt 114; RFC 8908 JSON contains the actual portal url */
                $this->oDhcp4->szCaptivePortalUri = "http://" . MiscNet::DwordToIpv4String($this->dwIpv4Address) . "/";
            }
            $this->oDhcp4->Subscribe("dhcp4_up", $this, "Stage2_OnDhcp4Up", null, true);
            $this->oDhcp4->Subscribe("dhcp4_err", $this, "Stage2_OnDhcp4Err", null, true);
            $this->oDhcp4->Subscribe("dhcp4_client_connected", $this, "OnIpv4ClientConnected", null, false);
            $this->oDhcp4->Subscribe("dhcp4_client_connected", $this, "OnPeerIsUp", null, false);
            $this->oDhcp4->BringUp();
            return;
        }

        /* no dhcp4 -> immediately trigger success signal */
        return $this->Stage2_OnDhcp4Up();
    }

    function Stage1b_OnWpadErr($szErrstr) {
        printf("[.] Stage1b_OnWpadErr\n");
        ScriptEngine::GetInstance()->SetErrstr("Could not bring up wpad server: " . $szErrstr);
        $this->Teardown();
        $this->PerformTransition("error");
    }

    function Stage1c_OnPortalErr($szErrstr) {
        printf("[.] Stage1c_OnPortalErr\n");
        ScriptEngine::GetInstance()->SetErrstr("Could not bring up captive portal server: " . $szErrstr);
        $this->Teardown();
        $this->PerformTransition("error");
    }

    function OnClientAuthorized($szClientIp) {
        printf("[i] OnClientAuthorized: %s\n", $szClientIp);
        if ($this->oDnsMitm !== null) {
            array_push($this->oDnsMitm->aAuthorizedIps, $szClientIp);
        }
        shell_exec("iptables -I VVTS_PORTAL 1 -s " . escapeshellarg($szClientIp) . " -j ACCEPT");
        ScriptEngine::GetInstance()->SetString("authorized_ip", $szClientIp);
        $this->PerformTransition("client_authorized");
    }

    function Stage1_OnHostApErr($szErrstr) {
        printf("[.] Stage1_OnHostApErr\n");
        ScriptEngine::GetInstance()->SetErrstr("Could not bring up access point: " . $szErrstr);
        $this->Teardown();
        $this->PerformTransition("error");
    }

    function Stage2_OnDhcp4Up() {
        printf("[.] Stage2_OnDhcp4Up\n");

        if ($this->abIpv6Address !== null) {
            /*
             * temporarily disable duplicate address detection so the ip address is applied immediately
             */
            file_put_contents("/proc/sys/net/ipv6/conf/" . $this->szApInterface . "/accept_dad", "0");
            $oInterfaceInfo = InterfaceInfo::FromInterface($this->szApInterface);
            /* set eiu-64 link-local ip address (mac-address based) */
            $abLinkLocalAddress = "\xfe\x80\x00\x00\x00\x00\x00\x00";
            $abLinkLocalAddress .= chr(ord($oInterfaceInfo->abMacAddress[0]) ^ 0x02);
            $abLinkLocalAddress .= substr($oInterfaceInfo->abMacAddress, 1, 2);
            $abLinkLocalAddress .= "\xff\xfe";
            $abLinkLocalAddress .= substr($oInterfaceInfo->abMacAddress, 3, 3);
            $szErrstr = shell_exec(
                "ifconfig " .
                    escapeshellarg($this->szApInterface) .
                    " inet6 add " .
                    escapeshellarg(MiscNet::BinaryToIpv6String($abLinkLocalAddress)) . "/64 2>&1"
            );

            if ($szErrstr !== "" && $szErrstr !== null) {
                ScriptEngine::GetInstance()->SetErrstr("Error configuring interface " . $this->szApInterface);
                goto _error;
            }

            /* also set the ip address from the state machine definition */
            $dwIpv6PrefixLen = ($this->dwIpv6PrefixLen === null) ? 64 : $this->dwIpv6PrefixLen;

            $szErrstr = shell_exec(
                "ifconfig " .
                    escapeshellarg($this->szApInterface) .
                    " inet6 add " .
                    escapeshellarg(MiscNet::BinaryToIpv6String($this->abIpv6Address) . "/" . intval($dwIpv6PrefixLen)) . " 2>&1"
            );

            if ($szErrstr !== "" && $szErrstr !== null) {
                ScriptEngine::GetInstance()->SetErrstr("Error configuring interface " . $this->szApInterface);
                goto _error;
            }
            /* restore duplicate address detection */
            file_put_contents("/proc/sys/net/ipv6/conf/" . $this->szApInterface . "/accept_dad", "1");

            if ($this->bSlaacEnable) {
                $this->oSlaac = new SlaacAdvertiser();
                $this->oSlaac->szInterface = $this->szApInterface;
                $this->oSlaac->abDns = $this->abSlaacDns;
                $this->oSlaac->dwLifetime = $this->dwSlaacLifetime;
                $this->oSlaac->szDomain = $this->szSlaacDomain;
                foreach($this->aSlaacStaticRoutes as $oRoute) {
                    $this->oSlaac->SetStaticRoute($oRoute->abAddress, $oRoute->dwPrefixLen);
                }
                $this->oSlaac->bNat64Enable = $this->bNat64Enable;
                $this->oSlaac->Subscribe("slaac_up", $this, "Stage3_OnSlaacUp", null, true);
                $this->oSlaac->Subscribe("slaac_err", $this, "Stage3_OnSlaacErr", null, true);
                $this->oSlaac->Subscribe("slaac_renew", $this, "OnSlaacRenew", null, false);
                $this->oSlaac->BringUp();
                return;
            }
        }

        /* no slaac -> immediately trigger success signal */
        return $this->Stage3_OnSlaacUp();

_error:
        file_put_contents("/proc/sys/net/ipv6/conf/" . $this->szApInterface . "/accept_dad", "1");
        $this->Teardown();
        return $this->PerformTransition("error");
    }

    function Stage2_OnDhcp4Err($szErrstr) {
        printf("[.] Stage2_OnDhcp4Err\n");
        ScriptEngine::GetInstance()->SetErrstr("Could not bring up dhcp4 server: " . $szErrstr);
        $this->Teardown();
        $this->PerformTransition("error");
    }

    function Stage3_OnSlaacUp() {
        printf("[.] Stage3_OnSlaacUp\n");

        if ($this->abIpv6Address !== null && $this->bNat64Enable) {
            /* enable ipv6 -> ipv4 address translation */
            $this->oNat64 = new Nat64();
            $this->oNat64->szInterface = $this->szApInterface;
            $this->oNat64->Subscribe("nat64_up", $this, "Stage4_OnNat64Up", null, true);
            $this->oNat64->Subscribe("nat64_err", $this, "Stage4_OnNat64Err", null, true);
            $this->oNat64->BringUp();
            return;
        }

        /* nat64 not enabled, trigger success signal */
        return $this->Stage4_OnNat64Up();
    }

    function Stage3_OnSlaacErr($szErrstr) {
        printf("[.] Stage3_OnSlaacErr\n");
        ScriptEngine::GetInstance()->SetErrstr("Could not bring up slaac advertiser: " . $szErrstr);
        $this->Teardown();
        $this->PerformTransition("error");
    }

    function Stage4_OnNat64Up() {
        printf("[.] Stage4_OnNat64Up\n");

        if ($this->bDnsEnable || $this->szCaptivePortalMode !== null) {
            $this->oDnsMitm = new DnsMitm();
            $this->oDnsMitm->dwBindAddr = $this->dwIpv4Address;
            $this->oDnsMitm->abBindIpv6Addr = $this->abIpv6Address;
            foreach($this->aDnsOverridesA as $szDomainName => $szIpAddress) {
                $this->oDnsMitm->SetOverride($szDomainName, $szIpAddress);
            }
            foreach($this->aDnsOverridesAAAA as $szDomainName => $szIpAddress) {
                $this->oDnsMitm->SetOverride($szDomainName, $szIpAddress);
            }
            if ($this->szCaptivePortalMode !== null && $this->dwIpv4Address !== null) {
                $szPortalIp = MiscNet::DwordToIpv4String($this->dwIpv4Address);
                if ($this->szCaptivePortalMode === "dns_all") {
                    $this->oDnsMitm->szCatchAllAddress = $szPortalIp;
                } else {
                    /* dns_detect: only spoof captive portal detection domains */
                    /* windows */
                    $this->oDnsMitm->SetOverride("www.msftconnecttest.com", $szPortalIp);
                    $this->oDnsMitm->SetOverride("ipv6.msftconnecttest.com", $szPortalIp);
                    /* android */
                    $this->oDnsMitm->SetOverride("connectivitycheck.gstatic.com", $szPortalIp);
                    $this->oDnsMitm->SetOverride("connectivitycheck.android.com", $szPortalIp);
                    /* apple */
                    $this->oDnsMitm->SetOverride("captive.apple.com", $szPortalIp);
                    $this->oDnsMitm->SetOverride("www.apple.com", $szPortalIp);
                    /* linux */
                    $this->oDnsMitm->SetOverride("nmcheck.gnome.org", $szPortalIp);
                }
            }
            $this->oDnsMitm->Subscribe("dns_up", $this, "Stage5_OnDnsUp", null, true);
            $this->oDnsMitm->Subscribe("dns_err", $this, "Stage5_OnDnsErr", null, true);
            $this->oDnsMitm->BringUp();
            return;
        }

        return $this->Stage5_OnDnsUp();
    }

    function Stage4_OnNat64Err($szErrstr) {
        printf("[.] Stage4_OnNat64Err\n");
        ScriptEngine::GetInstance()->SetErrstr("Could not bring up nat64 interface: " . $szErrstr);
        $this->Teardown();
        $this->PerformTransition("error");
    }

    function Stage5_OnDnsUp() {
        printf("[.] Stage5_OnDnsUp\n");
        if ($this->dwIpv4Address !== null && $this->bRouteToDefault) {
            $dwIpv4Netmask = ($this->dwIpv4Netmask === null) ? MiscNet::Ipv4StringToDword("255.255.255.0") : $this->dwIpv4Netmask;
            $dwPrefixLen = MiscNet::NetmaskToPrefixLength($dwIpv4Netmask);
            $aRouteTable = MiscNet::GetRouteTable();
            $oDefaultRoute = null;
            $dwFirstHalfSubnet = $this->dwIpv4Address & $dwIpv4Netmask;
            $dwSecondHalfSubnet = $dwFirstHalfSubnet | (1 << (31 - $dwPrefixLen));
            $dwNetmaskHalf = ($dwIpv4Netmask >> 1) | 0x80000000;
            $oFirstHalf = null;
            $oSecondHalf = null;

            if ($dwPrefixLen === 32) {
                /* subnet consists of just us -- halving does not make sense */
                goto _skip_ipv4;
            }

            foreach($aRouteTable as $oRoute) {
                if ($oRoute->dwSubnet === 0 && $oRoute->dwNetmask === 0) {
                    $oDefaultRoute = $oRoute;
                }
                if ($oRoute->dwSubnet === $dwFirstHalfSubnet && $oRoute->dwNetmask === $dwNetmaskHalf) {
                    $oFirstHalf = $oRoute;
                } else if ($oRoute->dwSubnet === $dwSecondHalfSubnet && $oRoute->dwNetmask === $dwNetmaskHalf) {
                    $oSecondHalf = $oRoute;
                } 
            }

            if ($oDefaultRoute !== null) {
                if (!isset($oFirstHalf)) {
                    shell_exec(
                        "ip route" .
                            " add " . escapeshellarg(MiscNet::DwordToIpv4String($dwFirstHalfSubnet)) . "/" . escapeshellarg($dwPrefixLen+1) .
                            (($oDefaultRoute->dwVia !== null) ? " via " . escapeshellarg(MiscNet::DwordToIpv4String($oDefaultRoute->dwVia)) : "") .
                            " dev " . escapeshellarg($oDefaultRoute->szDev)
                    );
                    array_push($this->aBacklog,
                        "ip route" .
                            " del " . escapeshellarg(MiscNet::DwordToIpv4String($dwFirstHalfSubnet)) . "/" . escapeshellarg($dwPrefixLen+1) .
                            " 2>/dev/null"
                        );
                }
                if (!isset($oSecondHalf)) {
                    shell_exec(
                        "ip route" .
                            " add " . escapeshellarg(MiscNet::DwordToIpv4String($dwSecondHalfSubnet)) . "/" . escapeshellarg($dwPrefixLen+1) .
                            (($oDefaultRoute->dwVia !== null) ? " via " . escapeshellarg(MiscNet::DwordToIpv4String($oDefaultRoute->dwVia)) : "") .
                            " dev " . escapeshellarg($oDefaultRoute->szDev)
                    );
                    array_push($this->aBacklog,
                        "ip route" .
                            " del " . escapeshellarg(MiscNet::DwordToIpv4String($dwSecondHalfSubnet)) . "/" . escapeshellarg($dwPrefixLen+1) .
                            " 2>/dev/null"
                    );
                }
            }
        }

_skip_ipv4:
        if ($this->abIpv6Address !== null && $this->bRouteToDefault) {
            $dwIpv6PrefixLen = ($this->dwIpv6PrefixLen === null) ? 64 : $this->dwIpv6PrefixLen;
            $aRouteTable = MiscNet::GetRouteTableIpv6();
            $oDefaultRoute = null;
            /* get subnet from ipv6 address and prefix len */
            $abFirstHalfSubnet = "";
            for ($i = 0; $i < 16; $i++) {
                if ($i < ($dwIpv6PrefixLen >> 3)) {
                    $abFirstHalfSubnet .= $this->abIpv6Address[$i];
                } else if ($i == ($dwIpv6PrefixLen >> 3)) {
                    $abFirstHalfSubnet .= chr(ord($this->abIpv6Address[$i]) & (0xff00 >> ($dwIpv6PrefixLen & 7)));
                } else {
                    $abFirstHalfSubnet .= "\x00";
                }
            }
            /* flip the bit immediately following the subnet prefix */
            $abSecondHalfSubnet = $abFirstHalfSubnet;
            $abSecondHalfSubnet[$dwIpv6PrefixLen >> 3] = chr(ord($abSecondHalfSubnet[$dwIpv6PrefixLen >> 3]) | (0x80 >> ($dwIpv6PrefixLen & 7)));
            $dwPrefixLenHalf = $dwIpv6PrefixLen + 1;
            $oFirstHalf = null;
            $oSecondHalf = null;

            if ($dwIpv6PrefixLen === 128) {
                /* subnet consists of just us -- halving does not make sense */
                goto _skip_ipv6;
            }

            foreach($aRouteTable as $oRoute) {
                if ($oRoute->abSubnet === str_repeat("\x00", 16) && $oRoute->dwPrefixLen === 0) {
                    $oDefaultRoute = $oRoute;
                }
                if ($oRoute->abSubnet === $abFirstHalfSubnet && $oRoute->dwPrefixLen === $dwPrefixLenHalf) {
                    $oFirstHalf = $oRoute;
                } else if ($oRoute->abSubnet === $abSecondHalfSubnet && $oRoute->dwPrefixLen === $dwPrefixLenHalf) {
                    $oSecondHalf = $oRoute;
                } 
            }

            if ($oDefaultRoute === null) {
                $szIpv6DefaultRoute = shell_exec("ip -6 route get ::");
                $szIpv6DefaultDev = null;
                $szIpv6DefaultVia = null;
                if (preg_match('/ via ([^\s]+) /', $szIpv6DefaultRoute, $aMatchDefaultVia)) {
                    $szIpv6DefaultVia = $aMatchDefaultVia[1];
                }
                if (preg_match('/ dev ([^\s]+) /', $szIpv6DefaultRoute, $aMatchDefaultDev)) {
                    $szIpv6DefaultDev = $aMatchDefaultDev[1];
                    $oDefaultRoute = new RouteIpv6(
                        str_repeat("\x00", 16), 0,
                        $szIpv6DefaultVia === null ? null : MiscNet::Ipv6StringToBinary($szIpv6DefaultVia),
                        $szIpv6DefaultDev, null
                    );
                }
            }

            if ($oDefaultRoute !== null) {
                if (!isset($oFirstHalf)) {
                    shell_exec(
                        "ip -6 route" .
                            " add " . escapeshellarg(MiscNet::BinaryToIpv6String($abFirstHalfSubnet)) . "/" . intval($dwPrefixLenHalf) .
                            (($oDefaultRoute->abVia !== null) ? " via " . escapeshellarg(MiscNet::BinaryToIpv6String($oDefaultRoute->abVia)) : "") .
                            " dev " . escapeshellarg($oDefaultRoute->szDev)
                    );
                    array_push($this->aBacklog,
                        "ip -6 route" .
                            " del " . escapeshellarg(MiscNet::BinaryToIpv6String($abFirstHalfSubnet)) . "/" . intval($dwPrefixLenHalf) .
                            " 2>/dev/null"
                        );
                }
                if (!isset($oSecondHalf)) {
                    shell_exec(
                        "ip -6 route" .
                            " add " . escapeshellarg(MiscNet::BinaryToIpv6String($abSecondHalfSubnet)) . "/" . intval($dwPrefixLenHalf) .
                            (($oDefaultRoute->abVia !== null) ? " via " . escapeshellarg(MiscNet::BinaryToIpv6String($oDefaultRoute->abVia)) : "") .
                            " dev " . escapeshellarg($oDefaultRoute->szDev)
                    );
                    array_push($this->aBacklog,
                        "ip -6 route" .
                            " del " . escapeshellarg(MiscNet::BinaryToIpv6String($abSecondHalfSubnet)) . "/" . intval($dwPrefixLenHalf) .
                            " 2>/dev/null"
                    );
                }

            }
        }

_skip_ipv6:
        if (($this->abIpv6Address !== null || $this->dwIpv4Address != null) && $this->bRouteToDefault) {
            $this->oArpResponder = new ArpResponder($this->szApInterface);
            $this->oArpResponder->Subscribe("arp_up", $this, "Stage6_OnArpUp", null, true);
            $this->oArpResponder->Subscribe("arp_err", $this, "Stage6_OnArpErr", null, true);
            $this->oArpResponder->Subscribe("peer_is_up", $this, "OnPeerIsUp", null, false);
            $this->oArpResponder->BringUp();
            return;
        }

        return $this->Stage6_OnArpUp();

_error:
        $this->Teardown();
        $this->PerformTransition("error");
    }

    function Stage5_OnDnsErr($szErrstr) {
        printf("[.] Stage5_OnDnsErr\n");
        ScriptEngine::GetInstance()->SetErrstr("Could not bring up dns server: " . $szErrstr);
        $this->Teardown();
        $this->PerformTransition("error");
    }

    function Stage6_OnArpUp() {
        printf("[.] Stage6_OnArpUp\n");
        $this->PerformTransition("success");
    }

    function Stage6_OnArpErr($szErrstr) {
        printf("[.] Stage6_OnArpErr\n");
        ScriptEngine::GetInstance()->SetErrstr("Could not bring up arp responder: " . $szErrstr);
        $this->Teardown();
        $this->PerformTransition("error");
    }

    function OnIpv4ClientConnected($szIpv4Address) {
        ScriptEngine::GetInstance()->SetString("renew_addr", $szIpv4Address);
        $this->PerformTransition("dhcp4_renew");
    }

    function OnSlaacRenew($szIpv6Address) {
        $abIpv6Address = MiscNet::Ipv6StringToBinary($szIpv6Address);
        if (!in_array($abIpv6Address, $this->aabSlaacNeighbors, true)) {
            array_push($this->aabSlaacNeighbors, $abIpv6Address);
        }
        ScriptEngine::GetInstance()->SetString("renew_addr", $szIpv6Address);
        $this->PerformTransition("slaac_renew");
    }

    function OnSlaacRenewAll() {
        foreach($this->aabSlaacNeighbors as $abNeighbor) {
            $this->OnSlaacRenew($abNeighbor);
        }
    }

    function OnPeerIsUp($szIpAddress) {
        /*
         * routing the subnet towards default causes packets destined for our clients
         * to be sent towards our default gateway (e.g. responses are bounced back on the wan interface).
         * to fix that, we add a route table entry for each client know to exist.
         * in case we are not routing the subnet towards the default, there's no need to do anything
         */
        if (!$this->bRouteToDefault) {
            return;
        }

        $dwIpv4Address = MiscNet::Ipv4StringToDword($szIpAddress);
        $abIpv6Address = MiscNet::Ipv6StringToBinary($szIpAddress);

        if ($dwIpv4Address !== false && $dwIpv4Address === $this->dwIpv4Address) {
            return;
        } else if ($abIpv6Address !== false && $abIpv6Address === $this->abIpv6Address) {
            return;
        }

        foreach($this->aPerClientRoutes as $i => $oPerClientRoute) {
            if ($dwIpv4Address !== false && $dwIpv4Address === $oPerClientRoute->dwIpv4Address) {
                return;
            }
            if ($abIpv6Address !== false && $abIpv6Address === $oPerClientRoute->abIpv6Address) {
                return;
            }
        }

        $oPerClientRoute = new PerClientRoute($dwIpv4Address, $abIpv6Address);
        array_push($this->aPerClientRoutes, $oPerClientRoute);
        if ($dwIpv4Address !== false) {
            printf("[i] added peer %s in known peer list\n", MiscNet::DwordToIpv4String($dwIpv4Address));
            MiscNet::AddRoute($dwIpv4Address, false, false, $this->szApInterface);
        } else if ($abIpv6Address !== false) {
            printf("[i] added peer %s in known peer list\n", MiscNet::BinaryToIpv6String($abIpv6Address));
            MiscNet::AddRouteIpv6($abIpv6Address, false, false, $this->szApInterface);
        }

    }

    function StateMachineSet_wifi_interface($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("wifi_interface must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->szWifiInterface = null;
        } else {
            $this->szWifiInterface = $oValue->szLiteral;
        }
    }

    function StateMachineSet_wifi_driver($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("wifi_driver must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->szWifiDriver = null;
        } else {
            $this->szWifiDriver = $oValue->szLiteral;
        }
    }

    function StateMachineSet_wifi_ssid($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("wifi_ssid must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->szWifiSsid = null;
        } else {
            $this->szWifiSsid = $oValue->szLiteral;
        }
    }

    function StateMachineSet_wifi_passphrase($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("wifi_passphrase must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->szWifiPassphrase = null;
        } else {
            $this->szWifiPassphrase = $oValue->szLiteral;
        }
    }

    function StateMachineSet_wifi_channel($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("wifi_channel must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->dwWifiChannel = null;
        } else if (intval($oValue->szLiteral) > 0) {
            $this->dwWifiChannel = intval($oValue->szLiteral);
        }
    }

    function StateMachineSet_ipv4_addr($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("ipv4_addr must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->dwIpv4Address = null;
        } else if (($dwIpv4Address = MiscNet::Ipv4StringToDword($oValue->szLiteral)) === false) {
            throw new ScriptInvokeError("invalid ipv4 address: " . $oValue->szLiteral);
        } else {
            $this->dwIpv4Address = $dwIpv4Address;
        }
    }

    function StateMachineSet_ipv4_netmask($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("ipv4_netmask must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->dwIpv4Netmask = null;
        } else if (($dwIpv4Netmask = MiscNet::Ipv4StringToDword($oValue->szLiteral)) === false) {
            throw new ScriptInvokeError("invalid ipv4 address: " . $oValue->szLiteral);
        } else {
            for($bOn = 0, $i = 0; $i < 32; $i++) {
                if ($dwIpv4Netmask & (1 << $i)) {
                    if (!$bOn) { $bOn = 1; }
                } else {
                    if ($bOn) { throw new ScriptInvokeError("invalid ipv4 netmask " . $oValue->szLiteral); }
                }
            }
            $this->dwIpv4Netmask = $dwIpv4Netmask;
        }
    }

    function StateMachineSet_ipv6_addr($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("ipv6_addr must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->abIpv6Address = null;
        } else if (($abIpv6Address = MiscNet::Ipv6StringToBinary($oValue->szLiteral)) === false) {
            throw new ScriptInvokeError("invalid ipv6 address: " . $oValue->szLiteral);
        } else {
            $this->abIpv6Address = $abIpv6Address;
        }
    }

    function StateMachineSet_ipv6_prefixlen($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("ipv6_prefixlen must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->dwIpv6PrefixLen = null;
        } else {
            $this->dwIpv6PrefixLen = intval($oValue->szLiteral);
        }
    }

    function StateMachineSet_dhcp4_enable($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("dhcp4_enable must be of type string");
        }

        $this->bDhcp4Enable = trim(strtolower($oValue->szLiteral)) === "true" || intval(trim($oValue->szLiteral)) !== 0;
    }

    function StateMachineSet_dhcp4_avoid($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("dhcp4_avoid must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->dwDhcp4Avoid = null;
        } else if (($dwDhcp4Avoid = MiscNet::Ipv4StringToDword($oValue->szLiteral)) === false) {
            throw new ScriptInvokeError("invalid ipv4 address: " . $oValue->szLiteral);
        } else {
            $this->dwDhcp4Avoid = $dwDhcp4Avoid;
        }
    }

    function StateMachineSet_dhcp4_leasetime($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("dhcp4_leasetime must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->dwDhcp4LeaseTime = null;
        } else if (
            ($dwDhcp4LeaseTime = intval($oValue->szLiteral)) === false ||
            $dwDhcp4LeaseTime <= 0
        ) {
            throw new ScriptInvokeError("invalid value for lease time: " . $oValue->szLiteral);
        } else {
            $this->dwDhcp4LeaseTime = $dwDhcp4LeaseTime;
        }
    }

    function StateMachineSet_dhcp4_domain($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("dhcp4_domain must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->szDhcp4Domain = null;
        } else {
            $this->szDhcp4Domain = $oValue->szLiteral;
        }
    }

    function StateMachineSet_dhcp4_dns($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("dhcp4_dns must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->dwDhcp4Dns = null;
        } else if (($dwDhcp4Dns = MiscNet::Ipv4StringToDword($oValue->szLiteral)) === false) {
            throw new ScriptInvokeError("invalid ipv4 address: " . $oValue->szLiteral);
        } else {
            $this->dwDhcp4Dns = $dwDhcp4Dns;
        }
    }

    function StateMachineSet_dhcp4_router($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("dhcp4_router must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->dwDhcp4Router = null;
        } else if (($dwDhcp4Router = MiscNet::Ipv4StringToDword($oValue->szLiteral)) === false) {
            throw new ScriptInvokeError("invalid ipv4 address: " . $oValue->szLiteral);
        } else {
            $this->dwDhcp4Router = $dwDhcp4Router;
        }
    }

    function StateMachineInvoke_dhcp4_static_route(...$aArguments) {
        if (count($aArguments) != 3) {
            throw new ScriptInvokeError("dhcp4_static_route requires three arguments");
        } else if (
            !($aArguments[0] instanceof ScriptStringLiteral) ||
            !($aArguments[1] instanceof ScriptStringLiteral) ||
            !($aArguments[2] instanceof ScriptStringLiteral)
        ) {
            throw new ScriptInvokeError("dhcp4_static_route requires three string parameters");
        }
        list ($oIpAddress, $oNetmask, $oGateway) = $aArguments;
        if (($dwIpAddress = MiscNet::Ipv4StringToDword($oIpAddress->szLiteral)) === false) {
            throw new ScriptInvokeError("Invalid IP address: " . $oIpAddress->szLiteral);
        } else if (($dwNetmask = MiscNet::Ipv4StringToDword($oNetmask->szLiteral)) === false) {
            throw new ScriptInvokeError("Invalid IP address: " . $oNetmask->szLiteral);
        } else if (($dwGateway = MiscNet::Ipv4StringToDword($oGateway->szLiteral)) === false) {
            throw new ScriptInvokeError("Invalid IP address: " . $oGateway->szLiteral);
        }

        for($bOn = 0, $i = 0; $i < 32; $i++) {
            if ($dwNetmask & (1 << $i)) {
                if (!$bOn) { $bOn = 1; }
            } else {
                if ($bOn) { throw new ScriptInvokeError("invalid ipv4 netmask " . $oNetmask->szLiteral); }
            }
        }

        array_push($this->aDhcp4StaticRoutes, new StaticRoute($dwIpAddress, $dwNetmask, $dwGateway));

        return new ScriptVoid();
    }

    function StateMachineInvoke_dhcp4_clear_static_routes(...$aArguments) {
        if (count($aArguments) != 0) {
            throw new ScriptInvokeError("dhcp4_clear_static_route does not require an argument");
        }

        $this->aDhcp4StaticRoutes = [];
        return new ScriptVoid();
    }

    function StateMachineSet_dhcp4_static_route_option($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("dhcp4_static_route_option must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->dwDhcp4StaticRouteOption = 121;
        } else if ($oValue->szLiteral !== "121" && $oValue->szLiteral !== "249") {
            throw new ScriptInvokeError("dhcp4_static_route_option must be \"121\" or \"249\", got: " . $oValue->szLiteral);
        } else {
            $this->dwDhcp4StaticRouteOption = intval($oValue->szLiteral);
        }
    }

    function StateMachineSet_dhcp4_netmask($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("dhcp4_netmask must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->dwDhcp4Netmask = null;
        } else if (($dwDhcp4Netmask = MiscNet::Ipv4StringToDword($oValue->szLiteral)) === false) {
            throw new ScriptInvokeError("invalid ipv4 address: " . $oValue->szLiteral);
        } else {
            for($bOn = 0, $i = 0; $i < 32; $i++) {
                if ($dwDhcp4Netmask & (1 << $i)) {
                    if (!$bOn) { $bOn = 1; }
                } else {
                    if ($bOn) { throw new ScriptInvokeError("Invalid IPv4 netmask"); }
                }
            }
            $this->dwDhcp4Netmask = $dwDhcp4Netmask;
        }
    }

    function StateMachineSet_dhcp4_wpad_proxy($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("dhcp4_wpad_proxy must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->szDhcp4WpadProxy = null;
        } else if (!preg_match('/^[^:]+:[0-9]+$/', $oValue->szLiteral)) {
            throw new ScriptInvokeError("dhcp4_wpad_proxy must be in host:port format, got: " . $oValue->szLiteral);
        } else {
            $this->szDhcp4WpadProxy = $oValue->szLiteral;
        }
    }

    function StateMachineSet_dhcp4_wpad_direct($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("dhcp4_wpad_direct must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->szDhcp4WpadDirect = null;
        } else {
            $this->szDhcp4WpadDirect = $oValue->szLiteral;
        }
    }

    function StateMachineSet_dhcp4_wpad_proxy_hosts($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("dhcp4_wpad_proxy_hosts must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->szDhcp4WpadProxyHosts = null;
        } else {
            foreach(array_filter(explode(';', $oValue->szLiteral)) as $szEntry) {
                $aParts = explode('=', trim($szEntry), 2);
                if (count($aParts) !== 2 || !preg_match('/^[^:]+:[0-9]+$/', trim($aParts[1]))) {
                    throw new ScriptInvokeError("dhcp4_wpad_proxy_hosts entries must be in host=proxyhost:port format, got: " . trim($szEntry));
                }
            }
            $this->szDhcp4WpadProxyHosts = $oValue->szLiteral;
        }
    }

    function StateMachineSet_dhcp4_wpad_url($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("dhcp4_wpad_url must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->szDhcp4WpadUrl = null;
        } else if (!preg_match('/^https?:\/\/.+/', $oValue->szLiteral)) {
            throw new ScriptInvokeError("dhcp4_wpad_url must be a valid http:// or https:// URL, got: " . $oValue->szLiteral);
        } else {
            $this->szDhcp4WpadUrl = $oValue->szLiteral;
        }
    }

    function StateMachineSet_captive_portal_mode($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("captive_portal_mode must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->szCaptivePortalMode = null;
        } else if ($oValue->szLiteral !== "dns_detect" && $oValue->szLiteral !== "dns_all") {
            throw new ScriptInvokeError("captive_portal_mode must be \"dns_detect\" or \"dns_all\", got: " . $oValue->szLiteral);
        } else {
            $this->szCaptivePortalMode = $oValue->szLiteral;
        }
    }

    function StateMachineSet_captive_portal_page($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("captive_portal_page must be of type string");
        }

        $this->szCaptivePortalPage = ($oValue->szLiteral === "") ? null : $oValue->szLiteral;
    }

    function StateMachineSet_captive_portal_redirect($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("captive_portal_redirect must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->szCaptivePortalRedirect = null;
        } else if (!preg_match('/^https?:\/\/.+/', $oValue->szLiteral)) {
            throw new ScriptInvokeError("captive_portal_redirect must be a valid http:// or https:// URL, got: " . $oValue->szLiteral);
        } else {
            $this->szCaptivePortalRedirect = $oValue->szLiteral;
        }
    }

    function StateMachineSet_dhcp4_captive_portal_uri($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("dhcp4_captive_portal_uri must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->szDhcp4CaptivePortalUri = null;
        } else if (!preg_match('/^https?:\/\/.+/', $oValue->szLiteral)) {
            throw new ScriptInvokeError("dhcp4_captive_portal_uri must be a valid http:// or https:// URL, got: " . $oValue->szLiteral);
        } else {
            $this->szDhcp4CaptivePortalUri = $oValue->szLiteral;
        }
    }

    function StateMachineInvoke_dhcp4_reload(...$aArguments) {
        if (count($aArguments) != 0) {
            throw new ScriptInvokeError("dhcp4_reload requires no arguments");
        }

        $bEnabled = $this->oDhcp4 !== null;
        if ($bEnabled && !$this->bDhcp4Enable) {
            $this->oDhcp4->Teardown();
            $this->oDhcp4 = null;
            goto _end;
        } else if (!$bEnabled && $this->bDhcp4Enable) {
            $this->oDhcp4 = new DhcpServer();
            $this->oDhcp4->Subscribe("dhcp4_client_connected", $this, "OnIpv4ClientConnected", null, false);
            $this->oDhcp4->Subscribe("dhcp4_client_connected", $this, "OnPeerIsUp", null, false);
        }

        $this->oDhcp4->szInterface = $this->szApInterface;
        $this->oDhcp4->dwDns = $this->dwDhcp4Dns;
        $this->oDhcp4->dwRouter = $this->dwDhcp4Router;
        $this->oDhcp4->dwAvoid = $this->dwDhcp4Avoid;
        $this->oDhcp4->dwLeaseTime = $this->dwDhcp4LeaseTime;
        $this->oDhcp4->szDomain = $this->szDhcp4Domain;
        $this->oDhcp4->ClearStaticRoutes();
        foreach($this->aDhcp4StaticRoutes as $oRoute) {
            $this->oDhcp4->SetStaticRoute($oRoute->dwAddress, $oRoute->dwNetmask, $oRoute->dwGateway);
        }
        $this->oDhcp4->dwNetmask = $this->dwDhcp4Netmask;
        $this->oDhcp4->dwStaticRouteOption = $this->dwDhcp4StaticRouteOption;
        if ($this->szDhcp4WpadUrl !== null) {
            $this->oDhcp4->szWpadUrl = $this->szDhcp4WpadUrl;
        } else if ($this->szDhcp4WpadProxy !== null) {
            if ($this->oWpadServer === null) {
                $this->oWpadServer = new WpadServer();
                $this->oWpadServer->szBindAddr = MiscNet::DwordToIpv4String($this->dwIpv4Address);
                $this->oWpadServer->szProxyAddr = $this->szDhcp4WpadProxy;
                if ($this->szDhcp4WpadDirect !== null) {
                    foreach(array_filter(explode(';', $this->szDhcp4WpadDirect)) as $szHost) {
                        array_push($this->oWpadServer->aDirectHosts, trim($szHost));
                    }
                }
                if ($this->szDhcp4WpadProxyHosts !== null) {
                    foreach(array_filter(explode(';', $this->szDhcp4WpadProxyHosts)) as $szEntry) {
                        $aParts = explode('=', trim($szEntry), 2);
                        if (count($aParts) === 2) {
                            $this->oWpadServer->aProxyHosts[trim($aParts[0])] = trim($aParts[1]);
                        }
                    }
                }
                $this->oWpadServer->BringUp();
            }
            $this->oDhcp4->szWpadUrl = "http://" . MiscNet::DwordToIpv4String($this->dwIpv4Address) . "/wpad.dat";
        } else {
            $this->oDhcp4->szWpadUrl = null;
        }
        if (!$bEnabled) {
            $this->oDhcp4->BringUp();
        } else {
            $this->oDhcp4->Reload();
        }
_end:
        return new ScriptVoid();
    }

    function StateMachineInvoke_dhcp4_renew(...$aArguments) {
        if (count($aArguments) != 1) {
            throw new ScriptInvokeError("dhcp4_renew requires an argument");
        } else if (!($aArguments[0] instanceof ScriptState)) {
            throw new ScriptInvokeError("dhcp4_renew requires a state type argument");
        }

        $oRenewState = $aArguments[0];
        $this->aTransitions["dhcp4_renew"] = ScriptEngine::GetInstance()->RegisterStateTransition($oRenewState);
        return new ScriptVoid();
    }

    function StateMachineSet_slaac_enable($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("slaac_enable must be of type string");
        }

        $this->bSlaacEnable = trim(strtolower($oValue->szLiteral)) === "true" || intval(trim($oValue->szLiteral)) !== 0;
    }

    function StateMachineSet_slaac_domain($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("slaac_domain must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->szSlaacDomain = null;
        } else {
            $this->szSlaacDomain = $oValue->szLiteral;
        }
    }

    function StateMachineSet_slaac_dns($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("slaac_dns must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->abSlaacDns = null;
        } else if (($abSlaacDns = MiscNet::Ipv6StringToBinary($oValue->szLiteral)) === false) {
            throw new ScriptInvokeError("invalid ipv6 address: " . $oValue->szLiteral);
        } else {
            $this->abSlaacDns = $abSlaacDns;
        }
    }

    function StateMachineSet_slaac_lifetime($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("slaac_lifetime must be of type string");
        }

        if ($oValue->szLiteral === "") {
            $this->dwSlaacLifetime = null;
        } else if (
            ($dwSlaacLifetime = intval($oValue->szLiteral)) === false ||
            $dwSlaacLifetime <= 0
        ) {
            throw new ScriptInvokeError("invalid value for slaac lifetime: " . $oValue->szLiteral);
        } else {
            $this->dwSlaacLifetime = $dwSlaacLifetime;
        }
    }

    function StateMachineInvoke_slaac_static_route(...$aArguments) {
        if (count($aArguments) != 2) {
            throw new ScriptInvokeError("slaac_static_route requires two arguments");
        } else if (
            !($aArguments[0] instanceof ScriptStringLiteral) ||
            !($aArguments[1] instanceof ScriptStringLiteral)
        ) {
            throw new ScriptInvokeError("slaac_static_route requires two string parameters");
        }
        list ($oIpv6Address, $oPrefixLen) = $aArguments;
        if (($abIpv6Address = MiscNet::Ipv6StringToBinary($oIpv6Address->szLiteral)) === false) {
            throw new ScriptInvokeError("Invalid IPv6 address: " . $szIpv6Address);
        } else if (($dwPrefixLen = intval($oPrefixLen->szLiteral)) < 0 || $dwPrefixLen > 128) {
            throw new ScriptInvokeError("Invalid prefix length: " . $oPrefixLen->szLiteral);
        }
        array_push($this->aSlaacStaticRoutes, new StaticIpv6Route($abIpv6Address, $dwPrefixLen));

        return new ScriptVoid();
    }

    function StateMachineInvoke_slaac_clear_static_routes(...$aArguments) {
        if (count($aArguments) != 0) {
            throw new ScriptInvokeError("slaac_clear_static_route does not require an argument");
        }

        $this->aSlaacStaticRoutes = [];
        return new ScriptVoid();
    }

    function StateMachineInvoke_slaac_reload(...$aArguments) {
        if (count($aArguments) != 0) {
            throw new ScriptInvokeError("slaac_reload requires no arguments");
        }

        $bEnabled = $this->oSlaac !== null;
        if ($bEnabled && !$this->bSlaacEnable) {
            $this->oSlaac->Teardown();
            $this->oSlaac = null;
            goto _end;
        } else if (!$bEnabled && $this->bSlaacEnable) {
            $this->oSlaac = new SlaacAdvertiser();
            $this->aabSlaacNeighbors = [];
            $this->oSlaac->Subscribe("slaac_renew", $this, "OnSlaacRenew", null, false);
        }

        $this->oSlaac->szInterface = $this->szApInterface;
        $this->oSlaac->abDns = $this->abSlaacDns;
        $this->oSlaac->dwLifetime = $this->dwSlaacLifetime;
        $this->oSlaac->szDomain = $this->szSlaacDomain;
        $this->oSlaac->ClearStaticRoutes();
        foreach($this->aSlaacStaticRoutes as $oRoute) {
            $this->oSlaac->SetStaticRoute($oRoute->abAddress, $oRoute->dwPrefixLen);
        }
        $this->oSlaac->bNat64Enable = $this->bNat64Enable;
        /*
         * router advertisement is sent over multicast with no confirmation,
         * so we assume all clients have renewed their routing information once the RA is sent out
         */
        $this->oSlaac->Subscribe("slaac_up", $this, "OnSlaacRenewAll", null, true);
        if (!$bEnabled) {
            $this->oSlaac->BringUp();
        } else {
            $this->oSlaac->Reload();
        }
_end:
        return new ScriptVoid();
    }

    function StateMachineInvoke_slaac_renew(...$aArguments) {
        if (count($aArguments) != 1) {
            throw new ScriptInvokeError("slaac_renew requires an argument");
        } else if (!($aArguments[0] instanceof ScriptState)) {
            throw new ScriptInvokeError("slaac_renew requires a state type argument");
        }

        $oRenewState = $aArguments[0];
        $this->aTransitions["slaac_renew"] = ScriptEngine::GetInstance()->RegisterStateTransition($oRenewState);
        return new ScriptVoid();
    }

    function StateMachineInvoke_nat64_reload(...$aArguments) {
        if (count($aArguments) != 0) {
            throw new ScriptInvokeError("nat64_reload requires no arguments");
        }

        $bEnabled = $this->oNat64 !== null;
        if ($bEnabled == $this->bNat64Enable) {
            /* nat64 has no parameters beyond bNat64Enable, so no need to reload anything */
            goto _end;
        }

        if (!$this->bNat64Enable) {
            $this->oNat64->Teardown();
            $this->oNat64 = null;
        } else {
            $this->oNat64 = new Nat64();
            $this->oNat64->szInterface = $this->szApInterface;
            $this->oNat64->BringUp();
        }

        /* bNat64Enable is also used by slaac, so we reload it as well */
        $this->StateMachineInvoke_slaac_reload();
_end:
        return new ScriptVoid();
    }

    function StateMachineSet_nat64_enable($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("nat64_enable must be of type string");
        }

        $this->bNat64Enable = trim(strtolower($oValue->szLiteral)) === "true" || intval(trim($oValue->szLiteral)) !== 0;
    }

    function StateMachineSet_route_to_default($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("route_to_default must be of type string");
        }

        $this->bRouteToDefault = trim(strtolower($oValue->szLiteral)) === "true" || intval(trim($oValue->szLiteral)) !== 0;
    }

    function StateMachineInvoke_dns_set_override(...$aArguments) {
        if (count($aArguments) != 2) {
            throw new ScriptInvokeError("set_override requires two arguments");
        } else if (!($aArguments[0] instanceof ScriptStringLiteral) || !($aArguments[1] instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("set_override requires two string parameters");
        }
        list ($oDomainName, $oIpAddress) = $aArguments;
        if (MiscNet::Ipv4StringToDword($oIpAddress->szLiteral) !== false) {
            $this->aDnsOverridesA[strtolower($oDomainName->szLiteral)] = $oIpAddress->szLiteral;
        } else if (MiscNet::Ipv6StringToBinary($oIpAddress->szLiteral) !== false) {
            $this->aDnsOverridesAAAA[strtolower($oDomainName->szLiteral)] = $oIpAddress->szLiteral;
        } else {
            throw new ScriptInvokeError("Invalid IP address: " . $oIpAddress->szLiteral);
        }
        
        return new ScriptVoid();
    }

    function StateMachineSet_dns_enable($oValue) {
        if (!($oValue instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("dns_enable must be of type string");
        }

        $this->bDnsEnable = trim(strtolower($oValue->szLiteral)) === "true" || intval(trim($oValue->szLiteral)) !== 0;
    }

    function StateMachineInvoke_deauth(...$aArguments) {
        if (count($aArguments) != 1) {
            throw new ScriptInvokeError("deauth requires an argument");
        } else if (!($aArguments[0] instanceof ScriptStringLiteral)) {
            throw new ScriptInvokeError("deauth requres a string argument");
        }
        $szDeauthTarget = $aArguments[0]->szLiteral;
        $dwDeauthTarget = null;
        $abDeauthTarget = null;
        $szLowLevelAddr = null;

        if (($dwDeauthTarget = MiscNet::Ipv4StringToDword($szDeauthTarget)) !== null) {
            $szNeighborTable = shell_exec("ip -4 neighbor");
        } else if (($abDeauthTarget = MiscNet::Ipv6StringToBinary($szDeauthTarget)) !== null) {
            $szNeighborTable = shell_exec("ip -6 neighbor");
        } else {
            throw new ScriptInvokeError("Invalid IP address: " . $szDeauthTarget);
        }

        $aszNeighborTable = preg_split("/\r?\n/s", $szNeighborTable);
        foreach($aszNeighborTable as $szNeighbor) {
            list($szNeighborAddr, $szRest) = explode(" ", $szNeighbor, 2);
            if (
                ($dwDeauthTarget != null && MiscNet::Ipv4StringToDword($szNeighborAddr) === $dwDeauthTarget) ||
                ($abDeauthTarget != null && MiscNet::Ipv6StringToBinary($szNeighborAddr) === $abNeighborTarget)
            ) {
                if (preg_match('/lladdr ([0-9a-f:]+)/', $szRest, $aMatchLowLevelAddr)) {
                    $szLowLevelAddr = $aMatchLowLevelAddr[1];
                    break;
                }
            }
        }

        if ($szLowLevelAddr === null) {
            throw new ScriptInvokeError("Unable to determine mac address for IP address " . $szDeauthTarget);
        }

        shell_exec("hostapd_cli deauth " . escapeshellarg($szLowLevelAddr));
        return new ScriptVoid();
    }

    function StateMachineInvoke_bring_up(...$aArguments) {
        if (count($aArguments) != 2) {
            throw new ScriptInvokeError("bring_up requires two arguments");
        } else if (!($aArguments[0] instanceof ScriptState) || !($aArguments[1] instanceof ScriptState)) {
            throw new ScriptInvokeError("bring_up requires a success state and an error state as parameters");
        } else if ($this->szWifiInterface == null) {
            throw new ScriptInvokeError("Please set wifi_interface before invoking bring_up()");
        } else if ($this->dwIpv4Address === null && $this->abIpv6Address === null) {
            throw new ScriptInvokeError("Please set either an ipv4 or an ipv6 address (or both) before invoking bring_up()");
        } else if ($this->dwIpv4Address === null && $this->bDhcp4Enable) {
            throw new ScriptInvokeError("dhcp4_enable requires setting an ipv4 address");
        } else if ($this->abIpv6Address === null && $this->bSlaacEnable) {
            throw new ScriptInvokeError("slaac_enable requires setting an ipv6 address");
        } else if ($this->abIpv6Address === null && $this->bNat64Enable) {
            throw new ScriptInvokeError("nat64_enable requires setting an ipv6 address");
        }

        list ($oSuccessState, $oErrorState) = $aArguments;
        $this->aTransitions["success"] = ScriptEngine::GetInstance()->RegisterStateTransition($oSuccessState);
        $this->aTransitions["error"] = ScriptEngine::GetInstance()->RegisterStateTransition($oErrorState);
        $this->oHostApd = new HostApd($this->szWifiInterface);
        $this->oHostApd->szDriver = $this->szWifiDriver;
        $this->oHostApd->szSsid = $this->szWifiSsid;
        $this->oHostApd->szPassphrase = $this->szWifiPassphrase;
        $this->oHostApd->dwChannel = $this->dwWifiChannel;
        $this->oHostApd->Subscribe("ap_up", $this, "Stage1_OnHostApUp", null, true);
        $this->oHostApd->Subscribe("ap_err", $this, "Stage1_OnHostApErr", null, true);
        $this->oHostApd->BringUp();
        return new ScriptVoid();
    }

    function StateMachineGet_ap_interface() {
        if ($this->oHostApd !== null) {
            return new ScriptStringLiteral($this->oHostApd->GetApInterface());
        }
        throw new ScriptInvokeError("hostap is not up, network interface does not exist");
    }
}

?>
