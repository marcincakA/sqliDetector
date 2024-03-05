<?php
include 'Classes/Tokenizer.php';
include 'Classes/MyToken.php';
$tokenizer = new Tokenizer('TestFile.php');
$tokens = $tokenizer->getTokens();
$hashMapOfLines = array();

foreach ($tokens as $token) {
    $lineNumber = $token->line;
    if ($lineNumber != $oldLineNumber) {
        $hashMapOfLines[$lineNumber][] = $line; // store line in hashmap
        //new line created
        $line = new Line($lineNumber, false);
    }
    $oldLineNumber = $lineNumber;

    $isVulnerable = false;
    //skip whitespace
    if ($token->id == 397){
        continue;
    }
    //vulnerable if string with parameters or mysqli_query
    if ($token->id == 319 || $token->text == 'mysqli_query'){
        $isVulnerable = true;
        $line->setVulnerable(); //set vulnerable line to true
    }

    echo "Token text => " . " " . $token->text. "  Token id => " . $token->id . " Token name => " . token_name($token->id) . " line: ". $token->line . " pos: " . $token->pos ."<br>";
    echo "<br>";
    $line->addToken(new MyToken($token, $isVulnerable));
}
echo "<br>";
?>