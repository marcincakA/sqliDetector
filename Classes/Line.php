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

    private bool $isUserInput;



    public function __construct(int $lineNumber, bool $isVulnerable)
    {
        $this->lineNumber = $lineNumber;
        $this->tokens = array();
        $this->isVulnerable = $isVulnerable;
        $this->isUserInput = false;
    }


    public function getTokens(): array
    {
        return $this->tokens;
    }

    public function getLineNumber(): int
    {
        return $this->lineNumber;
    }

    public function isUserInput(): bool
    {
        return $this->isUserInput;
    }

    //once user input, always user input
    public function setIsUserInput(): void
    {
        $this->isUserInput = true;
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