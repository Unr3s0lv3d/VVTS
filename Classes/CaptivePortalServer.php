<?php

namespace VVTS\Classes;

require_once(dirname(__FILE__) . "/../autoload.php");

use \VVTS\Classes\MainLoop;
use \VVTS\Classes\Subscribable;
use \VVTS\Interfaces\IUnblockable;

class CaptivePortalServer extends Subscribable implements IUnblockable {
    var $szBindAddr;
    var $szPortalPage;
    var $szRedirectUrl;
    var $szExternalPortalUrl;  /* wanneer gezet: OS-detectie redirect naar deze URL i.p.v. szBindAddr */
    var $szTmpDir;
    var $hProcess;
    var $hProcessStdout;
    var $hProcessStderr;

    function __construct() {
        parent::__construct();
        MainLoop::GetInstance()->RegisterObject($this);
    }

    function Sockets() {
        $aStreams = [];
        if ($this->hProcessStdout != null) {
            array_push($aStreams, $this->hProcessStdout);
        }
        if ($this->hProcessStderr != null) {
            array_push($aStreams, $this->hProcessStderr);
        }
        return $aStreams;
    }

    function Onunblock($hSocket) {
        $abBuf = fgets($hSocket, 1024);
        if ($abBuf === "" || $abBuf === false) {
            printf("[i] captive portal php server process ended\n");
            $this->Signal("portal_err", "php server process ended (port 80 in use?)");
            $this->Teardown();
            return;
        }
        printf("portal: %s", $abBuf);

        if (strpos($abBuf, "started") !== false) {
            printf("[i] captive portal server up\n");
            $this->Signal("portal_up");
        }

        if (($dwPos = strpos($abBuf, "authorized:")) !== false) {
            $szClientIp = trim(substr($abBuf, $dwPos + strlen("authorized:")));
            if (filter_var($szClientIp, FILTER_VALIDATE_IP) !== false) {
                printf("[i] client authorized: %s\n", $szClientIp);
                $this->Signal("client_authorized", $szClientIp);
            }
        }
    }

    function Teardown() {
        if ($this->hProcessStdout != null) {
            fclose($this->hProcessStdout);
            $this->hProcessStdout = null;
        }
        if ($this->hProcessStderr != null) {
            fclose($this->hProcessStderr);
            $this->hProcessStderr = null;
        }
        if ($this->hProcess != null) {
            $aStatus = proc_get_status($this->hProcess);
            if (isset($aStatus["running"]) && $aStatus["running"]) {
                posix_kill($aStatus["pid"], SIGTERM);
            }
            proc_close($this->hProcess);
            $this->hProcess = null;
        }
        if ($this->szTmpDir !== null) {
            @unlink($this->szTmpDir . "/router.php");
            @unlink($this->szTmpDir . "/portal.html");
            @rmdir($this->szTmpDir);
            $this->szTmpDir = null;
        }

        $this->CancelAllSubscriptions();
    }

    function BringUp() {
        if ($this->szBindAddr === null) {
            $this->Signal("portal_err", "Please set szBindAddr before invoking BringUp()");
            return;
        }

        $szRedirectUrl = ($this->szRedirectUrl !== null) ? $this->szRedirectUrl : "https://www.youtube.com/@Roelox";
        $szPortalUrl = ($this->szExternalPortalUrl !== null) ? $this->szExternalPortalUrl : "http://" . $this->szBindAddr . "/";

        $szRouterContent = <<<'ROUTER'
<?php
$method = $_SERVER['REQUEST_METHOD'];
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$clientIp = $_SERVER['REMOTE_ADDR'];

if ($method === 'POST' && $uri === '/authorize') {
    file_put_contents('php://stderr', "authorized:" . $clientIp . "\n");
    http_response_code(302);
    header('Location: REDIRECT_URL');
    exit;
}

$aDetectionPaths = [
    '/connecttest.txt',
    '/redirect',
    '/generate_204',
    '/gen_204',
    '/hotspot-detect.html',
    '/library/test/success.html',
    '/success.txt',
    '/check_network_status.txt',
    '/ncsi.txt',
];

foreach ($aDetectionPaths as $szPath) {
    if ($uri === $szPath || strpos($uri, $szPath) === 0) {
        http_response_code(302);
        header('Location: PORTAL_URL');
        exit;
    }
}

http_response_code(200);
header('Content-Type: text/html');
readfile(__DIR__ . '/portal.html');
ROUTER;

        $szRouterContent = str_replace('REDIRECT_URL', $szRedirectUrl, $szRouterContent);
        $szRouterContent = str_replace('PORTAL_URL', $szPortalUrl, $szRouterContent);

        if ($this->szPortalPage !== null && file_exists($this->szPortalPage)) {
            $szPortalContent = file_get_contents($this->szPortalPage);
        } else {
            $szPortalContent = "<html><head><title>Network Access</title></head><body>" .
                "<h1>Network Access</h1>" .
                "<p>Please accept the terms and conditions to access the internet.</p>" .
                "<form method='POST' action='http://" . $this->szBindAddr . "/authorize'>" .
                "<button type='submit'>Accept &amp; Continue</button>" .
                "</form></body></html>";
        }

        $this->szTmpDir = sys_get_temp_dir() . "/portal_" . uniqid();
        if (!mkdir($this->szTmpDir)) {
            $this->Signal("portal_err", "Could not create temporary directory");
            return;
        }
        file_put_contents($this->szTmpDir . "/router.php", $szRouterContent);
        file_put_contents($this->szTmpDir . "/portal.html", $szPortalContent);

        $aSpec = [
            0 => ["file", "/dev/null", "r"],
            1 => ["pipe", "w"],
            2 => ["pipe", "w"]
        ];

        $this->hProcess = proc_open(
            "exec php -S " . escapeshellarg($this->szBindAddr . ":80") . " -t " . escapeshellarg($this->szTmpDir) . " " . escapeshellarg($this->szTmpDir . "/router.php"),
            $aSpec,
            $aPipes
        );
        $this->hProcessStdout = $aPipes[1];
        $this->hProcessStderr = $aPipes[2];
    }
}

?>
