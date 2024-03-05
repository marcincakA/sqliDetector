<?php
    class Tokenizer {
        private $file;
        private $tokens;

        public function __construct($file) {
            $this->file = $file;
            $this->tokens = PhpToken::tokenize(file_get_contents($file));
        }

        /**
         * @return array
         */
        public function getTokens() : array
        {
            return $this->tokens;
        }
    }
?>