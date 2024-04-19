<?php
include_once "Classes/Analyzer.php";
function analyze($projectPath, $mode) {
    //handle if file not found
        if (!file_exists($projectPath)) {
            echo "File not found";
            return;
        }
    if ($mode == '-r'){
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
    if ($mode == '-n') {
        $analyzer = new Analyzer($projectPath);
        $analyzer->analyzeExecutionPoints();
        $analyzer->printVulnerabilitiesConsole();
    }
}

analyze($argv[1], $argv[2]);
//analyze("C:\Users\marci\PhpstormProjects\InjectionDetector");