<?php
include_once "Classes/Analyzer.php";
function analyze($projectPath) {
    //handle if file not found
    if(!file_exists($projectPath)) {
        echo "File not found";
        return;
    }
    $fileIterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($projectPath));

    $vulnerabilitiesCount = 0;

    foreach ($fileIterator as $file) {
        if ($file->isDir()) {
            continue;
        }

        if (pathinfo($file->getFilename(), PATHINFO_EXTENSION) !== 'php') {
            continue;
        }

        $analyzer = new Analyzer($file->getPathname());
        $analyzer->analyzeExecutionPoints();
        echo $file->getFilename() . "\n";
        $analyzer->printVulnerabilitiesConsole();
    }
}

analyze($argv[1]);