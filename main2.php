<?php
include_once "Classes/Analyzer.php";


$analyzer = new Analyzer('TestFile.php');

$analyzer->printLines();
