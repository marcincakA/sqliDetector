<?php
//Neda sa dedit od phpToken lebo je final, tak vytvorim obalovaciu triedu
class MyToken
{
    private bool $isVulnerable;
    private PhpToken $token;

    public function __construct(PhpToken $token, bool $isVulnerable)
    {
        $this->token = $token;
        $this->isVulnerable = $isVulnerable;
    }

    public function isVulnerable(): bool
    {
        return $this->isVulnerable;
    }

    public function getToken(): PhpToken
    {
        return $this->token;
    }
}

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
