<?php
include_once 'Classes/Tokenizer.php';
include_once 'Classes/MyToken.php';
include_once 'Classes/Line.php';

class Analyzer
{
    //hashMap kluc - premenna, hodnota - pole riadkov kde sa nachadza
    private array $variablesHashMap;

    //hashMap kluc - cislo riadku, hodnota - riadok (pole tokenov)
    //pouzita na zobrazenie pre pouzivatela
    private array $linesHashMapAll;


    //hashMap kluc - cislo riadku, hodnota - riadok (pole tokenov)
    private array $linesHashMap;
    //pole indexov riadkov, ktore obsahuju SQL query exectution point (zatial mysqli_query a mysqli_real_query)
    private array $sqlExecutionPoints;

    //pole zranitelnosti
    private array $vulnerabilities;

    //hashMap kluc - premenna, hodnota - bool ci je premenna sanitizovana
    private array $checkedVariables;
    private Tokenizer $tokenizer;



    public function __construct(string $file)
    {
        $this->tokenizer = new Tokenizer($file);
        $this->variablesHashMap = array();
        $this->linesHashMap = array();
        $this->vulnerabilities = array();
        $this->sqlExecutionPoints = array();
        $this->checkedVariables = array();
        $this->linesHashMapAll = array();

        $this->init();
    }

    /**
     * @return void
     * Inicializacia analyzera
     * Rozdeli tokeny do riadkov a ulozi ich do hashMapy
     * Ulozi vsetky premenne do hashMapy
     * Ulozi vsetky SQL execution points do pola
     */
    private function init() : void {
        $tokens = $this->tokenizer->getTokens();
        $line = null;
        $lineDisplay = null;
        $oldLineNumber = 0;
        //$position = 0;
        foreach ($tokens as $token) {
            $lineNumber = $token->line;
            if ($lineNumber != $oldLineNumber) {
                if ($line != null) {
                    $this->linesHashMap[$oldLineNumber] = $line;
                    $this->linesHashMapAll[$oldLineNumber] = $lineDisplay;
                }
                //new line created
                $line = new Line($lineNumber, false);
                //new line for display purposes
                $lineDisplay = new Line($lineNumber, false);
                //$position = 0;
            }
            //display line add everything
            $lineDisplay->addToken(new MyToken($token, false));
            $isVulnerable = false;
            $oldLineNumber = $lineNumber;
            if ($token->id == 317) {
                $this->variablesHashMap[$token->text][] = $token->line;
            }
            //skip whitespace and comments
            if ($token->id == 397 || $token->id == 392){
                continue;
            }
            //zatial to necham takto a kazdy string s parametrom bude vulnerable
            if ($token->id == 319){
                $line->setVulnerable();
                $isVulnerable = true;
            }
            //najde vykonavanie sqlPrikazu a zapise do pola
            //todo object oriented style, mozno staci pozmenit hodnotu v ''0
            //alebo vsetko co konci na query je povazovane za exec point??
            //alebo pozri ci koniec txtu (substring) obsahuje query
            //if($token->text == 'mysqli_query' || $token->text == 'mysqli_real_query' || $token->text == 'mysqli_multi_query') {
            if(str_contains(($token->text),'query')) {
                $line->setVulnerable();
                $isVulnerable = true;
                $this->sqlExecutionPoints[] = $lineNumber;
            }

            $line->addToken(new MyToken($token, $isVulnerable)); // store tokens in line class
        }
    }

    public function getVariablesHashMap(): array
    {
        return $this->variablesHashMap;
    }

    public function getLinesHashMap(): array
    {
        return $this->linesHashMap;
    }

    public function getVulnerabilities(): array
    {
        return $this->vulnerabilities;
    }

    public function getTokenizer(): Tokenizer
    {
        return $this->tokenizer;
    }

    public function printLines() : void {
        foreach ($this->linesHashMap as $line) {
            $value = $line->isVulnerable() ? "is vulnerable" : "is not vulnerable";
            echo "<br>";
            echo "Line number: " . $line->getLineNumber() . " " . $value ."<br>";
            $Mytokens = $line->getTokens();
            foreach ($Mytokens as $token) {
                echo "Token text => " . " " . $token->getToken()->text. "  Token id => " . $token->getToken()->id . "; Token name => " . token_name($token->getToken()->id) . " line: ". $token->getToken()->line . " pos: " . $token->getToken()->pos ."<br>";
            }
        }

        //print exec points
        echo "<br>";
        echo "SQL Execution Points: ";
        foreach ($this->sqlExecutionPoints as $point) {
            echo $point . " ";
        }
    }

    /**
     * @return void
     * Analyzuje vykonavacie body SQL prikazov
     * Prechadza riadky a hlada vykonavacie body
     */
    public function analyzeExecutionPoints() : void {
        foreach ($this->sqlExecutionPoints as $point) {
            $line = $this->linesHashMap[$point];
            $tokens = $line->getTokens();
            $exPointFound = false;
            $position = 0;
            foreach ($tokens as $token) {
                //monentalne pracuje na proceduralnej urovni
                //todo object oriented style
                //if ($token->getToken()->text == 'mysqli_query' || $token->getToken()->text == 'mysqli_real_query') {
                if(str_contains(($token->getToken()->text),'query')) {
                    $exPointFound = true;
                    //Hladaj od konca do bodu v ktorom sa nasiel exec point
                    $this->findSQLCommand($line, $position);
                }
                $position++;
            }
        }
    }

    /*
     * Procedural style
     * mysqli_real_query(mysqli $mysql, string $query): bool
     * mysqli_query(mysqli $mysql, string $query, int $resultmode = MYSQLI_STORE_RESULT): mysqli_result|bool
     * 1st param is connection
     * 2nd param is query
     * */
    private function findSQLCommand($line, $position) : void {
        $tokens = $line->getTokens();
        $exPointFound = false;
        //$position = 0;
        $lineSize = count($tokens) - 1;
        $commandIsFound = false;
        for($i = $lineSize; $i > $position; $i--) {
            //317 T_VARIABLE
            if ($tokens[$i]->getToken()->id ==  317) {
                //searchVariable();
                //echo("Variable found: " . $tokens[$i]->getToken()->text . "<br>");
                /**/
                $this->searchVariableForSQLCommand($tokens[$i]->getToken()->text);
            }
        }
    }

    /**
     * @param string $variable
     * @return void
     * Prehladavanie riadkov v ktorych sa nachadza premenna hladanie slov INSERT && INTO, UPDATE && SET, DELETE && FROM, SELECT && FROM
     */
    private function searchVariableForSQLCommand(string $variable) : void
    {
        $lines = $this->variablesHashMap[$variable];
        foreach ($lines as $line) {
            $line = $this->linesHashMap[$line];
            $tokens = $line->getTokens();
            $position = 0;
            $counter = 0;
            //$isSafe = false;
            foreach ($tokens as $token) {
                //podmienky na hladanie prikazov
                if ($token->getToken()->id !=  319) {
                    $position = $counter;
                    continue;
                }
                //to lower pre jednoduhsie hladanie
                $foundStatement = strtolower($token->getToken()->text);
                //320 T_CONSTANT_ENCAPSED_STRING -> string s parametrom // sanca na zranitelny sql prikaz
                if (str_contains($foundStatement, 'select') && str_contains($foundStatement, 'from') ||
                    str_contains($foundStatement, 'insert') && str_contains($foundStatement, 'into') ||
                    str_contains($foundStatement, 'update') && str_contains($foundStatement, 'set') ||
                    str_contains($foundStatement, 'delete') && str_contains($foundStatement, 'from')) {
                    {
                        //poslem prikaz ktory sa nasiel aj s pozicou v riadku
                        $this->isSQLComandSafe($line, $position);
                    }
                }
                $counter++;
            }
        }
    }

    /**
     * @param $line
     * @param $position
     * @return bool
     * Kontroluje ci je SQL prikaz bezpecny
     * 1. krok - najde vsetky premenne v SQL prikaze
     * 2. krok - prejde vsetky premenne a zisti ci su zranitelne
     */
    public function isSQLComandSafe($line, $position) : bool {

        $tokens = $line->getTokens();
        $lineSize = count($tokens) - 1;
        $variablesToCheck = array();
        //krok 1
        for($i = $lineSize; $i > $position; $i--) {
            //find variables
            if ($tokens[$i]->getToken()->id ==  317) {
                //echo("SQL command found: " . $tokens[$i]->getToken()->text . "<br>");
                $variablesToCheck[] = $tokens[$i]->getToken()->text;
            }

        }
        //krok 2
        if (count($variablesToCheck) != 0){
            foreach ($variablesToCheck as $variable) {
                if(!$this->isSanitazed($variable, $line->getLineNumber())){
                    $this->vulnerabilities[] = $variable . " is not sanitized";
                    return false;
                }
            }
        }
        return true;
    }

    //momentale sa spolieha na to ze nebude prepisana po prvom vstupe
    //mozno lepsie prehodit a zacat od spodku ak je prvy vyskyt od spodku zranitelny $_GET/$_POST tak automaticky false?
    //Prejde vsetky riadky kde sa nachadza premenna a hlada ci sa niekde nachadza mysqli_real_escape_string
    private function isSanitazed($variable, $lineNumber) : bool {
        //kontrola ci uz bola premenna kontrolovana
        if (array_key_exists($variable, $this->checkedVariables)) {
            //ak raz bola kontrolovana vrat true, ak nebola kontrolovana ma moznost vratit false;
            return true;
        }

        $locations = $this->variablesHashMap[$variable];
        for($i = 0; $i < count($locations); $i++) {
            if ($locations[$i] >= $lineNumber) {
                $this->checkedVariables[$variable] = false;
                return false;
            }
            $tokens = $this->linesHashMap[$locations[$i]]->getTokens();
            foreach ($tokens as $token) {
                if (str_contains($token->getToken()->text, 'mysqli_real_escape_string')) {
                    $this->checkedVariables[$variable] = true;
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * @param $line
     * @param $position
     * Constructs SQL command from given line and position
     * Useless bullshit
     * @return string
     */
    private function constructSQLCommand($line, $position) : string {
        $tokens = $line->getTokens();
        $lineSize = count($tokens) - 1;
        $command = "";
            for($i = $position; $i <$lineSize; $i++) {
                if ($tokens[$i]->getToken()->id ==  34) {
                    break;
                }
                $command .= $tokens[$i]->getToken()->text;
            }
            return $command;
    }
    //naco ti je toto
    private function cutCommand($command) : string {

        return $command;
    }

    public function printVulnerabilities() : void {
        echo "<h1>Vulnerabilities:</h1> <br>";
        foreach ($this->vulnerabilities as $vulnerability) {
            echo $vulnerability . "<br>";
        }
    }

    /***
     * @return void
     * Show source code with highlighted vulnerabilities
     * 1.st step - parse checked variables and if they are vulnerable, add their position to array
     * 2.nd step - display source code with highlighted vulnerabilities
     */
    public function displayErrors() : void {
        //step 1, da sa aj $variable => $isVulnerable
        foreach ($this->checkedVariables as $variable => $isSanitized) {
            if (!$isSanitized) {
                $locations = $this->variablesHashMap[$variable];
                foreach ($locations as $location) {
                    $this->linesHashMapAll[$location]->setVulnerable();
                }
            }
        }

        //step 2
        foreach ($this->linesHashMapAll as $line) {
            $tokens = $line->getTokens();
            if ($line->isVulnerable()) {
                echo "<div style='background-color:#ff9966'>";
            }
            foreach ($tokens as $token) {
                echo $token->getToken()->text;
            }
            if ($line->isVulnerable()) {
                echo "</div>";
            }
            echo "<br>";
        }
    }


}


