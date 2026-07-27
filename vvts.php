<?php

require_once dirname(__FILE__) . "/prereq_check.php";
require_once dirname(__FILE__) . "/autoload.php";

use \VVTS\Classes\MainLoop;
use \VVTS\Classes\ScriptParseCtx;
use \VVTS\Classes\ScriptEngine;
use \VVTS\Types\ScriptDocument;

if (!isset($argv[1])) {
    printf("[i] usage: %s <state_machine_file>\n", $argv[0]);
    exit(0);
}

$szScript = @file_get_contents($argv[1]);
if ($szScript === false) {
    printf("[-] unable to read file " . $argv[1]);
    exit(-1);
}

$oMainLoop = MainLoop::GetInstance();
$oParseCtx = new ScriptParseCtx($szScript);
$oParsed = ScriptDocument::Parse($oParseCtx);

$oEngine = ScriptEngine::GetInstance();
$oEngine->RegisterScript($oParsed);
$oEngine->EnterInitState();
$oMainLoop->Loop();
  
?>