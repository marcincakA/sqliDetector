<?php
include_once 'Classes/Tokenizer.php';
include_once 'Classes/MyToken.php';
include_once 'Classes/Line.php';

class Analyzer
{
    private array $variablesHashMap;
    private array $linesHashMap;

    private array $vulnerabilities;
    private Tokenizer $tokenizer;

    public function __construct(string $file)
    {
        $this->tokenizer = new Tokenizer($file);
        $this->variablesHashMap = array();
        $this->linesHashMap = array();
        $this->vulnerabilities = array();

        $this->init();
    }

    private function init() {
        $tokens = $this->tokenizer->getTokens();
        $line = null;
        $oldLineNumber = 0;
        foreach ($tokens as $token) {
            $lineNumber = $token->line;
            if ($lineNumber != $oldLineNumber) {
                if ($line != null) {
                    $this->linesHashMap[$lineNumber] = $line;
                }
                //new line created
                $line = new Line($lineNumber, false);
            }
            $isVulnerable = false;
            $oldLineNumber = $lineNumber;
            if ($token->id == 397){
                continue;
            }
            if ($token->id == 319 || $token->text == "sqli_query" || $token->text == "sql_query"){
                $line->setVulnerable();
                $isVulnerable = true;
            }
            if ($line == null){
                continue;
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

    public function printLines() {
        foreach ($this->linesHashMap as $line) {
            $value = $line->isVulnerable() ? "is vulnerable" : "is not vulnerable";
            echo "Line number: " . $line->getLineNumber() . " " . $value ."<br>";
            $Mytokens = $line->getTokens();
            foreach ($Mytokens as $token) {
                echo "Token text => " . " " . $token->getToken()->text. "  Token id => " . $token->getToken()->id . " Token name => " . token_name($token->getToken()->id) . " line: ". $token->getToken()->line . " pos: " . $token->pos ."<br>";
            }
        }
    }

}