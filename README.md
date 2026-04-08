# VVTS

## Installation
```bash
# 1. Clone the repository
git clone -b test https://github.com/Unr3s0lv3d/VVTS
cd VVTS

# 2. Install dependencies
sudo apt-get install php hostapd iw udhcpd net-tools iproute2 iptables libbsd-dev bison flex -y

# 3. Build the project
sudo make
```

## Usage
```bash
# 4. Start VVTS with a statemachine file
sudo php vvts.php ./state_machines/statemachine.stm
```



