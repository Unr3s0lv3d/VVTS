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

The server is intended to be hosted on a publicly reachable machine, separate from the Raspberry Pi running the framework.
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

```bash
# 5. Verify the server is reachable
curl http://yourserver.com/?create_token
```

```bash
# 6. Usage in .stm file
mon.validation_server = "http://yourserver.com/";
```