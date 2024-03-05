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
?>
