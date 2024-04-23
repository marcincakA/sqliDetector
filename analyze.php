<?php
// main.php
include_once "Classes/Analyzer.php";
function analyze($projectPath, $mode) {
    //handle if file not found
        if (!file_exists($projectPath)) {
            echo "File not found";
            return;
        }
    // Check if the mode is valid
    if ($mode != '-r' && $mode != '-s') {
        echo "Error: Invalid mode. Use '-r' for recursive analysis or '-s' for single file analysis.\n";
        return;
    }
    if ($mode == '-r'){
        echo "********START********\n";
        $fileIterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($projectPath));
        foreach ($fileIterator as $file) {
            if ($file->isDir()) {
                continue;
            }
            if (pathinfo($file->getFilename(), PATHINFO_EXTENSION) !== 'php') {
                continue;
            }
            $analyzer = new Analyzer($file->getPathname());
            $analyzer->analyzeExecutionPoints();
            echo $file->getPathname() . "\n";
            $analyzer->printVulnerabilitiesConsole();
        }
        echo "********END********\n";
    }
    if ($mode == '-s') {
        $analyzer = new Analyzer($projectPath);
        $analyzer->analyzeExecutionPoints();
        $analyzer->printVulnerabilitiesConsole();
    }
}

if ($argc != 3) {
    echo "Error: Invalid number of arguments. Use 'php analyze.php <path> <mode>'\n";
    return;
}
analyze($argv[1], $argv[2]);
//analyze("C:\Users\marci\PhpstormProjects\InjectionDetector");