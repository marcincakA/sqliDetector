<?php
include_once "Classes/Analyzer.php";


$analyzer = new Analyzer('TestFile2.php');

$analyzer->analyzeExecutionPoints();

$analyzer->printLines();

$analyzer->printVulnerabilities();


