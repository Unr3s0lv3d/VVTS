<?php

if (posix_getuid() != 0) {
    throw new Exception("VVTS should run as root");
} else if (!file_exists(dirname(__FILE__) . "/src/arpresponder")) {
    throw new Exception("src/arpresponder is missing (forgot to run 'make'?)");
} else if (!file_exists(dirname(__FILE__) . "/src/trafficmonitor")) {
    throw new Exception("src/trafficmonitor is missing (forgot to run 'make'?)");
} else if (!file_exists(dirname(__FILE__) . "/external/radvd-2.20/radvd")) {
    throw new Exception("external/radvd-2.20/radvd is missing (forgot to run 'make'?)");
} else if (!file_exists(dirname(__FILE__) . "/external/tayga-0.9.5/tayga")) {
    throw new Exception("external/tayga-0.9.5/tayga is missing (forgot to run 'make'?)");
} else if (!file_exists(dirname(__FILE__) . "/external/phpqrcode/phpqrcode.php")) {
    throw new Exception("external/phpqrcode/phpqrcode.php is missing (forgot to run 'make'?)");
} else if (exec("which hostapd", $szOutput, $dwStatus) === false || $dwStatus !== 0) {
    throw new Exception("hostapd is missing on your system (please install)");
} else if (exec("which iw", $szOutput, $dwStatus) === false || $dwStatus !== 0) {
    throw new Exception("iw is missing on your system (please install)");
} else if (exec("which udhcpd", $szOutput, $dwStatus) === false || $dwStatus !== 0) {
    throw new Exception("udhcpd is missing on your system (please install)");
} else if (exec("which ifconfig", $szOutput, $dwStatus) === false || $dwStatus !== 0) {
    throw new Exception("ifconfig is missing on your system (please install)");
} else if (exec("which ip", $szOutput, $dwStatus) === false || $dwStatus !== 0) {
    throw new Exception("ip is missing on your system (please install)");
} else if (exec("which iptables", $szOutput, $dwStatus) === false || $dwStatus !== 0) {
    throw new Exception("iptables is missing on your system (please install)");
} else if (exec("which ip6tables", $szOutput, $dwStatus) === false || $dwStatus !== 0) {
    throw new Exception("ip6tables is missing on your system (please install)");
}

?>