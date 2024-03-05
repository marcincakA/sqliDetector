<?php
include_once "MyToken.php";
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

    public function addToken(MyToken $token): void
    {
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