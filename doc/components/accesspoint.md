# `accesspoint`

The `accesspoint` class handles all infrastructural aspects of the access point that is to be used. It is instantiated as follows:
```
ap = accesspoint();
```

## Methods

### `bring_up(state_up, state_err)`
Sets up the access point in accordance to the values set in the object's properties. The state machine enters state `state_up` if successful, and `state_err` in case of an error. At least `wifi_interface` and `ipv4_addr` or `ipv6_addr` must be set in order to set up the access point. A call to `bring_up` should occur _after_ all properties are set.

### `dhcp4_static_route(ip_addr, netmask, gateway)`
Instructs the DHCP4 server to provide a classless static route. By default this uses DHCP option 121. The `dhcp4_static_route_option` property can be set to `249` to use the Microsoft classless static route option instead. All three arguments are strings containing an IPv4 address. Changes take effect after invoking `bring_up()` or `dhcp4_reload()` on the object.

### `dhcp4_clear_static_routes()`
Clears the list of DHCP4 classless static routes to be provided by the DHCP4 server. Changes take effect after invoking `bring_up()` or `dhcp4_reload()` on the object.

### `dhcp4_reload()`
Causes changes in the object's properties pertaining to the DHCP4 server to be adopted.

### `dhcp4_renew(state_renew)`
Causes a state transition to `state_renew` to occur when a DHCP4 lease is created or renewed for a client. When entering that state, the `renew_addr` variable will be a string consisting of the address of said client.

### `slaac_static_route(ip6_addr, prefixlen)`
Similar to `dhcp4_static_route()`, instructs the SLAAC advertiser to advertise that IPv6 subnet `ip_addr` with prefix length `prefixlen` is to be routed through us (a gateway cannot be specified as routes can only be advertised on one's own behalf in SLAAC). `ip_addr` is a string containing an IPv6 address, `prefixlen` is a string containing the number `0` up to `128`. Changes take effect after invoking `bring_up()` or `slaac_reload()` on the object.

### `slaac_clear_static_routes()`
Similar to `dhcp4_clear_static_routes()`, clears the list of SLAAC routes to be advertised. Changes take effect after invoking `bring_up()` or `slaac_reload()` on the object.

### `slaac_reload()`
Similar to `dhcp4_reload()`, causes changes in the object's properties pertaining to the SLAAC advertiser to be adopted.

### `slaac_renew(state_renew)`
Similar to `dhcp4_renew()`, causes a state transition to `state_renew` to occur when a SLAAC neighbor advertisement is received. When entering that state, the `renew_addr` variable will be a string consisting of the address of the sender.

### `nat64_reload()`
Causes changes in the object's properties pertaining to NAT64 to be adopted.

### `dns_set_override(domain_name, ip_addr)`
Instructs the DNS mitm framework to spoof DNS results for `domain_name` to ip address `ip_addr`. `domain_name` is a string containing a domain name, whereas `ip_addr` is a string containing either an IPv4 or IPv6 address. Changes take effect immediately.

### `deauth(ip_addr)`
Forces the client with address `ip_addr` to de-authenticate -- i.e. disconnect. Usually causes the client to reconnect immediately.

## Writable properties

### `wifi_interface`
A string containing the name of the wifi network interface to be used for the access point, e.g. `wlan0`. Set before invoking `bring_up()`.

### `wifi_driver`
A string containing the driver used by hostapd to communicate with the network interface hardware, e.g. `nl80211` (the default) or `wext`. Set before invoking `bring_up()`.

### `wifi_ssid`
A string containing the _Extended Service Set Identifier (ESSID)_, a.k.a. _network name_ of the access point that is to be created. Set before invoking `bring_up()`.

### `wifi_passphrase`
A string containing the Wi-Fi password for the access point that is to be created. Do not set or set to empty string for no password. Set before invoking `bring_up()`.

### `wifi_channel`
A string containing the channel number for the access point that is to be created. Do not set or set to empty string in order to adopt the channel that the wireless network interface is currently on. Set before invoking `bring_up()`.

### `ipv4_addr`
A string containing the IPv4 address set to the access point that is to be created. Set before invoking `bring_up()`.

### `ipv4_netmask`
A string containing the IPv4 netmask set to the access point that is to be created. Set before invoking `bring_up()`.

### `ipv6_addr`
A string containing the IPv6 address set to the access point that is to be created. Set before invoking `bring_up()`.

### `ipv6_prefixlen`
A string containing the prefix length (in bits) set to the access point that is to be created. Set before invoking `bring_up()`.

### `dhcp4_enable`
A string containing a Boolean value determining whether a DHCP4 server should be set up on the access point that is to be created. Changes take effect after invoking `bring_up()` or `dhcp4_reload()` on the object.

### `dhcp4_avoid`
A string containing an IPv4 address that is not to be leased out by the DHCP4 server. Changes take effect after invoking `bring_up()` or `dhcp4_reload()` on the object.

### `dhcp4_leasetime`
A string containing the time in seconds a DHCP4 lease is considered valid and does not need to be renewed. Changes take effect after invoking `bring_up()` or `dhcp4_reload()` on the object.

### `dhcp4_domain`
A string containing the value for the _search domain_ field to be sent to DHCP4 clients, used by a resolver to create a fully qualified domain name (FQDN) from a relative name. Changes take effect after invoking `bring_up()` or `dhcp4_reload()` on the object.

### `dhcp4_dns`
A string containing the IPv4 address of the DNS server to be sent to DHCP4 clients. Changes take effect after invoking `bring_up()` or `dhcp4_reload()` on the object.

### `dhcp4_router`
A string containing the IPv4 address of the default route to be sent to DHCP4 clients. Changes take effect after invoking `bring_up()` or `dhcp4_reload()` on the object.

### `dhcp4_static_route_option`
A string containing the DHCP option number used for routes configured through `dhcp4_static_route()`. Valid values are `121` and `249`. The default is `121`. Changes take effect after invoking `bring_up()` or `dhcp4_reload()` on the object.

### `dhcp4_netmask`
A string containing the IPv4 netmask to be sent to DHCP4 clients through the DHCP subnet option. If unset, the netmask of the access point interface is used. Changes take effect after invoking `bring_up()` or `dhcp4_reload()` on the object.

### `dhcp4_wpad_url`
A string containing an `http://` or `https://` PAC file URL to advertise through DHCP option 252 (WPAD). The configured URL is advertised directly to DHCP clients. Changes take effect after invoking `bring_up()` or `dhcp4_reload()` on the object.

### `captive_portal_mode`
A string determining whether VVTS should start a captive portal server and spoof captive portal detection traffic. Valid values are `dns_detect` and `dns_all`. In `dns_detect` mode, VVTS only overrides known OS captive portal detection hostnames. In `dns_all` mode, VVTS sends all DNS A queries to the captive portal address and installs temporary firewall rules that only allow DHCP, DNS and HTTP until a client is authorized. Set before invoking `bring_up()`.

### `captive_portal_api`
A string containing an `http://` or `https://` URL to advertise through DHCP option 114 for captive portal discovery. If unset and `captive_portal_mode` is enabled, VVTS advertises the local captive portal API endpoint on the access point IPv4 address. Set before invoking `bring_up()`.

### `captive_portal_allow_https`
A semicolon-separated list of hostnames that should remain reachable over HTTPS (port 443) when `captive_portal_mode` is set to `dns_all`. For each hostname, VVTS resolves the IP address, adds an iptables rule allowing traffic to that IP on port 443, and configures a DNS override so the real IP is returned instead of the spoofed access point address. Set before invoking `bring_up()`.

### `captive_portal_allow_http`
A semicolon-separated list of hostnames that should remain reachable over HTTP (port 80) when `captive_portal_mode` is set to `dns_all`. Works the same as `captive_portal_allow_https` but for port 80. If a hostname appears in both `captive_portal_allow_https` and `captive_portal_allow_http`, the already-resolved IP from the HTTPS list is reused to avoid DNS inconsistencies. Set before invoking `bring_up()`.

### `captive_portal_user_url`
A string containing an `http://` or `https://` URL that the external server should return as the `user-portal-url` in its RFC 8908 JSON response. When set, VVTS sends a configure request to the server (derived from `captive_portal_api`) during `bring_up()` and an unconfigure request during teardown. Requires the `server_secret` variable to be set. Set before invoking `bring_up()`.

### `slaac_enable`
A string containing a Boolean value determining whether a SLAAC advertiser should be set up on the access point that is to be created. Changes take effect after invoking `bring_up()` or `slaac_reload()` on the object.

### `slaac_domain`
A string containing the value for the _search domain_ field to be contained in SLAAC advertisements, used by a resolver to create a fully qualified domain name (FQDN) from a relative name. Changes take effect after invoking `bring_up()` or `slaac_reload()` on the object.

### `slaac_dns`
A string containing the IPv6 address of the DNS server to be contained in SLAAC advertisements. Changes take effect after invoking `bring_up()` or `slaac_reload()` on the object.

### `slaac_lifetime`
A string containing the time in seconds a SLAAC advertisement is considered valid and does not need to be renewed. Changes take effect after invoking `bring_up()` or `slaac_reload()` on the object.

### `nat64_enable`
A string containing a Boolean value determining whether NAT64 should be set up on the access point that is to be created. The `64:ff9b::/96` prefix is used for routing IPv4 traffic. Set before invoking `bring_up()`.

### `route_to_default`
A string containing a Boolean value determining whether traffic intended for the local subnet is supposed to be forwarded to our default router. Setting this to `true` has the effect of spoofed responses to ARP and network solicitation packets being sent, causing clients to be under the impression to be communicating with a peer on the local subnet, whereas in reality communication is forwarded over the Internet. Set before invoking `bring_up()`.

### `dns_enable`
A string containing a Boolean value determining whether the internal DNS forwarder and responder should be enabled on the access point that is to be created. Set before invoking `bring_up()`.

## Readable properties

### `ap_interface`
A string containing the name of the virtual network interface pertaining to the access point.
