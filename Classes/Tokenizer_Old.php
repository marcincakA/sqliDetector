<?php

class Tokenizer_Old
{
    private $file;
    private $tokens;

    public function __construct($file)
    {
        $this->file = $file;
        $this->tokens = token_get_all(file_get_contents($file));
    }

    /**
     * @return array
     */
    public function getTokens()
    {
        return $this->tokens;
    }

}

