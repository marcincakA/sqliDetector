<?php
include_once "MyToken.php";
/*
 * Trieda reprezentujuca riadok kodu
 * Uklada tokeny do pola
 * Taktiez obsahuje atribut lineNumber, ktory reprezentuje cislo riadku pre jednoduhsi pristup v pripade hashmapy
 * */
class Line
{
    private int $lineNumber;
    private array $tokens;

    private bool $isVulnerable;

    public function __construct(int $lineNumber, bool $isVulnerable)
    {
        $this->lineNumber = $lineNumber;
        $this->tokens = array();
        $this->isVulnerable = $isVulnerable;
    }


    public function getTokens(): array
    {
        return $this->tokens;
    }

    public function getLineNumber(): int
    {
        return $this->lineNumber;
    }

    /*public function addToken(MyToken $token, int $position): void
    {
        //$this->tokens[$position][] = $token;
        $this->tokens[] = $token;
    }*/

    public function addToken(MyToken $token): void
    {
        //$this->tokens[$position][] = $token;
        $this->tokens[] = $token;
    }

    public function isVulnerable(): bool
    {
        return $this->isVulnerable;
    }

    //once vulnerable, always vulnerable
    public function setVulnerable() {
        $this->isVulnerable = true;
    }
}