# Main

Welcome to the _VVTS (VPN Vulnerability Testing Suite)_ documentation. This contains all the information to get you started with VVTS in order to validate a particular VPN client/OS combination against a number of known attacks, and how to quickly describe new attacks/variants to the framework in order for them to be evaluated.

## Funding

This project is funded through [VPN Fund](https://nlnet.nl/thema/VPNFund.html), a fund established by [NLnet](https://nlnet.nl). Learn more at the [NLnet project page](https://nlnet.nl/project/VPN-vulnerabilitytesting).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)


## Features

VVTS is a tool that allows one to evaluate susceptibility of a VPN client to a wide variety of attacks. It does so by configuring and bringing up the attack infrastructure, in the form of a wireless access point, including the necessary services, such as DHCP, DNS, Router Advertisements and IPv6 to IPv4 address translation, and providing additional domain-specific functionality to the user such as ARP spoofing and traffic redirection. Subsequently, a victim device connects to said wireless access point, establishes a VPN connection, and retrieves a URL reported by VVTS in a QR code. Finally, VVTS monitors traffic in order to determine and report whether the URL was retrieved directly or through the VPN tunnel, indicating a successful or unsuccessful attack, respectively.


VVTS uses a _state machine_ in order to describe an attack. The notation was chosen since it allow for all relevant settings to be contained within a single concise file, abstracting away details not relevant for the attack, while simultaneously maintaining the flexibilty to describe all network-based attacks currently found in public literature. The notation itself is described [here](notation.md), although it should quickly become obvious from the [examples](https://github.com/MidnightBlueLabs/VVTS/blob/main/state_machines). Currently, definition files for the following attacks exist:
* LocalNet[^mathy], for which there is a definition file for [IPv4](https://github.com/MidnightBlueLabs/VVTS/blob/main/state_machines/localnet.stm) and another for [IPv6](https://github.com/MidnightBlueLabs/VVTS/blob/main/state_machines/localnet_ipv6.stm).
* ServerIP[^mathy] [IPv4](https://github.com/MidnightBlueLabs/VVTS/blob/main/state_machines/serverip.stm), [IPv6](https://github.com/MidnightBlueLabs/VVTS/blob/main/state_machines/serverip_ipv6.stm).
* TunnelVision[^tunnelvision] [IPv4](https://github.com/MidnightBlueLabs/VVTS/blob/main/state_machines/tunnelvision.stm), [new route through DHCP renew (IPv4)](https://github.com/MidnightBlueLabs/VVTS/blob/main/state_machines/tunnelvision_dhcp_renew.stm), [IPv6](https://github.com/MidnightBlueLabs/VVTS/blob/main/state_machines/tunnelvision_ipv6.stm) and [new route through SLAAC renew (IPv6)](https://github.com/MidnightBlueLabs/VVTS/blob/main/state_machines/tunnelvision_slaac_renew.stm).

[^mathy]: [Xue, Nian, et al. "Bypassing tunnels: Leaking VPN client traffic by abusing routing tables." 32nd USENIX Security Symposium (USENIX Security 23). 2023](https://papers.mathyvanhoef.com/usenix2023-tunnelcrack.pdf).
[^tunnelvision]: [Cronce, Dani, et al. "TunnelVision: A local network VPN leaking technique that affects all routing-based VPNs](https://www.tunnelvisionbug.com/).

Besides the attacks found in public literature, one can describe new attacks and/or variants using the state machine notation. The following features are available as building blocks:
* Running a wireless access point using HostAP.
* Setting up a DHCPv4 server and/or a SLAAC instance for IPv6.
* Setting up firewall rules to allow for packet forwarding and/or masquerading.
* Setting up NAT64 to allow for IPv4 traffic to flow over IPv6.
* Spoofing DNS responses to a particular result.
* Spoofing ARP (IPv4) and/or Neightborhood Advertisement (IPv6) packets to pretend a particular host is on the local subnet.
* Monitoring the network interface to detect presence of VPN traffic and/or a successful bypass of the VPN tunnel.

## Components

VVTS consists of a main component (this) and a small server component ([Here](https://github.com/MidnightBlueLabs/VVTS_server)). The server component exists so that a reliable distinction can be made between the situation where traffic has flown through the VPN (and therefore unaffected by the attack in progress), and where traffic has (accidentally) flown through a different connection, such as a different Wi-Fi or cellular.

## Preparation

In order to get VVTS up and running, the following commands are expected to be available on your system:
* `php` (`sudo apt install php`)
* `hostapd` (`sudo apt install hostapd`)
* `iw` (`sudo apt install iw`)
* `udhcpd` (`sudo apt install udhcpd`)
* `ifconfig` (`sudo apt install net-tools`)
* `ip` (`sudo apt install iproute2`)
* `iptables` (`sudo apt install iptables`)
* `ip6tables` (`sudo apt install iptables`)
* `python3` (`sudo apt install python3`) — only required for WPAD attacks in local proxy mode

Furthermore, VVTS has the following dependencies:
* [PHP QR Code](https://phpqrcode.sourceforge.net/) for QR Code generation.
* [Linux IPv6 Router Advertisement Daemon (radvd)](https://radvd.litech.org/) for sending SLAAC advertisements.
* [Tayga](https://github.com/apalrd/tayga) for facilitating NAT64.
These dependencies are automatically retrieved and compiled as needed when issuing the `make` command.

Finally, VVTS is implemented in PHP and requires raw sockets in order to monitor and spoof packets. Raw sockets in PHP are supported since version `8.5.x`, which is quite rare at the time of writing. Consequently, in order to avoid having to deploy custom installations of PHP, the components `arpresponder` and `trafficmonitor` contained within VVTS are implemented in C. To enable maximum compatibility, these components are implemented as standalone binaries, rather than as extensions to PHP. Both components are automatically built when issuing the `make` command.

If all dependencies are satisfied and components are built, it is time to set up the [server component](https://github.com/MidnightBlueLabs/VVTS_server). Please refer to the [server component documentation](https://github.com/MidnightBlueLabs/VVTS_server/tree/main/doc) for information on how to do so.

At this point, you are ready to run VVTS. VVTS takes a state machine definition file as input, for example, like so:
```
sudo php vvts.php state_machines/localnet.stm
```
Make sure you understand `localnet.stm`, and change the name of the network interface and the URL of the server component as appropriate.