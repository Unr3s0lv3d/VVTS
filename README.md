# VPN Vulnerability Testing Suite (VVTS)

VVTS is a tool that allows one to evaluate susceptibility of a VPN client to a wide variety of attacks. It does so by configuring and bringing up the attack infrastructure, in the form of a wireless access point, including the necessary services, such as DHCP, DNS, Router Advertisements and IPv6 to IPv4 address translation, and providing additional domain-specific functionality to the user such as ARP spoofing and traffic redirection. Subsequently, a victim device connects to said wireless access point, establishes a VPN connection, and retrieves a URL reported by VVTS in a QR code. Finally, VVTS monitors traffic in order to determine and report whether the URL was retrieved directly or through the VPN tunnel, indicating a successful or unsuccessful attack, respectively.

## Funding

This project is funded through [VPN Fund](https://nlnet.nl/thema/VPNFund.html), a fund established by [NLnet](https://nlnet.nl). Learn more at the [NLnet project page](https://nlnet.nl/project/VPN-vulnerabilitytesting).

[<img src="https://nlnet.nl/logo/banner.png" alt="NLnet foundation logo" width="20%" />](https://nlnet.nl)

## Documentation

Please refer to the [VVTS Documentation](https://github.com/Unr3s0lv3d/VVTS/blob/test/doc/index.md) to get started.


# Installation for Raspberry Pi
```bash
# 1. Clone the repository
git clone -b test https://github.com/Unr3s0lv3d/VVTS.git
cd VVTS

# 2. Install dependencies
sudo apt-get install php hostapd iw udhcpd net-tools iproute2 iptables libbsd-dev bison flex -y

# 3. Build the project
sudo make

# 4. Verify dependencies
sudo php prereq_check.php
```



## Make vvts0 unmanaged
When VVTS starts, it creates a virtual wireless interface called vvts0. By default, NetworkManager will try to manage this interface, which can cause conflicts during operation. Setting it as unmanaged prevents NetworkManager from interfering.
```bash
# 4. Create new file
sudo nano /etc/NetworkManager/conf.d/unmanaged-vvts.conf

# 5. Content
[keyfile]
unmanaged-devices=interface-name:vvts0

```
## Usage
```bash
# 6. Start VVTS with a statemachine file
sudo php vvts.php ./state_machines/statemachine.stm
```



# Server Component
The VVTS Server is a lightweight PHP REST API that acts as an external validation endpoint. It generates unique tokens and tracks whether a test device has contacted it, including the IP address the request came from. This allows the framework to determine whether traffic reached the server directly (outside the VPN tunnel) or through the VPN.

The server is intended to be hosted on a publicly reachable machine, separate from the Raspberry Pi running the framework. The server source code is available at [VVTS_server](https://github.com/Unr3s0lv3d/VVTS_server/tree/test).
```bash
# 1. Install Webserver
sudo apt-get install apache2
```

```bash
# 2. Install dependencies
sudo apt-get install php php-sqlite3
```

```bash
# 3. Clone the repository
git clone -b test https://github.com/Unr3s0lv3d/VVTS_server.git
```

```bash
# 4. Remove default index page and copy files to web directory
sudo rm /var/www/html/index.html
sudo rsync -av --exclude='.git' VVTS_server/ /var/www/html/
sudo chown -R www-data:www-data /var/www/html/
```

## DNS and SSL

Point a domain name to your server by creating an **A record** (and optionally an **AAAA record** for IPv6). An HTTPS certificate is required for the captive portal feature. Client operating systems (notably Android) only accept the RFC 8908 captive portal API over HTTPS with a valid certificate.

You can use [Certbot](https://certbot.eff.org/) to obtain a free certificate from Let's Encrypt:
```bash
# 5. Install Certbot
sudo apt-get install certbot python3-certbot-apache -y

# 6. Obtain and install certificate
sudo certbot --apache -d yourserver.com
```

```bash
# 7. Verify the server is reachable
curl https://yourserver.com/?create_token
```

```bash
# 8. Usage in .stm file
mon.validation_server = "https://yourserver.com/";
```

## Configuring the state machines

The `.stm` files in `state_machines/` are example configurations. Before using them, you need to update the following values to match your own setup:

- **`mon.validation_server`** — the URL of your server component (e.g. `https://yourserver.com/`)
- **`ap.captive_portal_api`** — the captive portal API URL advertised via DHCP option 114 (RFC 8910), pointing to your external server
- **`ap.captive_portal_user_url`** — the URL returned by the server as `user-portal-url` in the RFC 8908 JSON (requires `server_secret`)
- **`ap.captive_portal_allow_https`** — semicolon-separated hostnames that remain reachable over HTTPS (port 443) through the captive portal firewall
- **`ap.captive_portal_allow_http`** — semicolon-separated hostnames that remain reachable over HTTP (port 80) through the captive portal firewall
- **`mon.vpn_endpoints`** — the VPN endpoint addresses for the VPN client you are testing
- **`server_secret`** — shared secret for server API calls (captive portal configuration, remote proxy). Must match `API_SECRET` in `api_config.php`
- **`proxy.server`** — the server URL for WPAD proxy attacks (e.g. `https://yourserver.com/`)
- **`proxy.mode`** — `"remote"` (default) to run the proxy on the server, or `"local"` to run the proxy on the Raspberry Pi
- **`proxy.local_addr`** — host:port of the local proxy as seen by clients (required when `proxy.mode` is `"local"`, e.g. `192.168.60.1:8080`)
- **`proxy.direct`** — semicolon-separated hosts that should bypass the proxy (e.g. `192.168.60.1`)
- **`ap.dhcp4_wpad_url`** — URL of the PAC file on the server (e.g. `https://yourserver.com/?wpad`)

For a full list of all properties and methods, see the [component documentation](doc/components/accesspoint.md).

## Server secret

The Raspberry Pi sends authenticated API requests to the server for the following features:

- **Captive portal configuration** — configures the `user-portal-url` returned by the server's RFC 8908 JSON response (`captive_portal_user_url` in the `.stm` file). Requires `captive_portal_api` and `server_secret` to be set.
- **Remote proxy (WPAD attacks)** — starts/stops a forward proxy on the server for WPAD-based attacks. Requires `proxy.server` and `server_secret` to be set.
- **Local proxy (WPAD attacks)** — configures a PAC file on the server that points clients to a proxy running on the Raspberry Pi. Requires `proxy.server`, `proxy.mode = "local"`, and `server_secret` to be set.

All API requests are authenticated using an `X-API-Secret` HTTP header.

On the server, edit `api_config.php` and set a strong secret:
```php
define("API_SECRET", "your-random-secret-here");
```

Use the same secret in the `.stm` file on the Raspberry Pi:
```
server_secret = "your-random-secret-here";
```

## WPAD proxy attacks

VVTS supports two proxy modes for WPAD-based attacks. Both require the server secret to be configured (see above).

### Remote proxy

The server component runs a forward proxy on a random port and generates a PAC file. This is the default mode (`proxy.mode = "remote"`).

```bash
# 1. Install the firewall wrapper script
sudo cp VVTS_server/vvts-proxy-fw.sh /usr/local/bin/vvts-proxy-fw.sh
sudo chmod 755 /usr/local/bin/vvts-proxy-fw.sh

# 2. Allow the web server to run only the wrapper script as root
sudo visudo
# Add the following line:
www-data ALL=(root) NOPASSWD: /usr/local/bin/vvts-proxy-fw.sh

# 3. Ensure python3 is installed on the server
sudo apt-get install python3 -y
```

See `state_machines/wpad_remote_proxy.stm` for a complete example.

### Local proxy

The Raspberry Pi runs a forward proxy locally and the server only hosts the PAC file (via `/?wpad`). Use `proxy.mode = "local"` and set `proxy.local_addr` to the address and port clients should connect to. This requires `python3` to be installed on the Raspberry Pi:

```bash
sudo apt-get install python3 -y
```

See `state_machines/wpad_local_proxy.stm` for a complete example.