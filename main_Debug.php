<?php
include_once "Classes/Analyzer.php";






$analyzer = new Analyzer('TestFiles\TestFileUnsafeStringInterpolation.php');

$analyzer->analyzeExecutionPoints();

$analyzer->printLines();

$analyzer->displayErrors();

$analyzer->printVulnerabilities();

$analyzer->printVulnerabilitiesConsole();

