<?php
include 'Classes/Tokenizer.php';
include 'Classes/MyToken.php';
$tokenizer = new Tokenizer('TestFile.php');
$tokens = $tokenizer->getTokens();
$vulnerable = array();
$hashMapOfLines = array();

foreach ($tokens as $token) {
    $lineNumber = $token->line;
    if ($lineNumber != $oldLineNumber) {
        //new line created
        $line = new Line($lineNumber, false);
    }
    $oldLineNumber = $lineNumber;

    $isVulnerable = false;
    if ($token->id == 397){
        continue;
    }
    if ($token->id == 319){
        $vulnerable[] = $token;
        $isVulnerable = true;
    }
    echo "Token text => " . " " . $token->text. "  Token id => " . $token->id . " Token name => " . token_name($token->id) . " line: ". $token->line . " pos: " . $token->pos ."<br>";
    echo "<br>";

    $hashMapOfLines[$lineNumber][] = new MyToken($token, $isVulnerable); // store tokens in a hashmap


}
echo "<br>";
?>