<?php
include_once 'Classes/Tokenizer.php';
include_once 'Classes/MyToken.php';
include_once 'Classes/Line.php';

class Analyzer
{
    //hashMap kluc - premenna, hodnota - pole riadkov kde sa nachadza
    private array $variablesHashMap;
    //hashMap kluc - cislo riadku, hodnota - riadok (pole tokenov)
    private array $linesHashMap;
    //pole indexov riadkov, ktore obsahuju SQL query exectution point (zatial mysqli_query a mysqli_real_query)
    private array $sqlExecutionPoints;

    //pole zranitelnosti zatial nevyuzite
    private array $vulnerabilities;
    private Tokenizer $tokenizer;

    public function __construct(string $file)
    {
        $this->tokenizer = new Tokenizer($file);
        $this->variablesHashMap = array();
        $this->linesHashMap = array();
        $this->vulnerabilities = array();
        $this->sqlExecutionPoints = array();

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
        $oldLineNumber = 0;
        //$position = 0;
        foreach ($tokens as $token) {
            $lineNumber = $token->line;
            if ($lineNumber != $oldLineNumber) {
                if ($line != null) {
                    $this->linesHashMap[$oldLineNumber] = $line;
                }
                //new line created
                $line = new Line($lineNumber, false);
                //$position = 0;
            }
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
            if($token->text == 'mysqli_query' || $token->text == 'mysqli_real_query') {
                $line->setVulnerable();
                $isVulnerable = true;
                $this->sqlExecutionPoints[] = $lineNumber;
            }

            $line->addToken(new MyToken($token, $isVulnerable)/*, $position*/); // store tokens in line class
            //$position++;
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
                if ($token->getToken()->text == 'mysqli_query' || $token->getToken()->text == 'mysqli_real_query') {
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
                echo("Variable found: " . $tokens[$i]->getToken()->text . "<br>");
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
        $found = false;
        $variablesToCheck = array();
        //krok 1
        for($i = $lineSize; $i > $position; $i--) {
            //find variables
            if ($tokens[$i]->getToken()->id ==  317) {
                //echo("SQL command found: " . $tokens[$i]->getToken()->text . "<br>");
                $found = true;
            }
            if ($found && $tokens[$i]->getToken()->id ==  317) {
                $variablesToCheck[] = $tokens[$i]->getToken()->text;
            }

        }
        //krok 2
        if ($found) {
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
        $locations = $this->variablesHashMap[$variable];
        for($i = 0; $i < count($locations); $i++) {
            if ($locations[$i] >= $lineNumber) {
                return false;
            }
            $tokens = $this->linesHashMap[$locations[$i]]->getTokens();
            foreach ($tokens as $token) {
                if (str_contains($token->getToken()->text, 'mysqli_real_escape_string')) {
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
        foreach ($this->vulnerabilities as $vulnerability) {
            echo $vulnerability . "<br>";
        }
    }
}


