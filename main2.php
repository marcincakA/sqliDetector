<?php
include_once "Classes/Analyzer.php";




$analyzer = new Analyzer('TestFile3_PDO.php');

$analyzer->analyzeExecutionPoints();

//$analyzer->printLines();

$analyzer->displayErrors();

$analyzer->printVulnerabilities();


