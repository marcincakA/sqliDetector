<?php
include 'Tokenizer_Old.php';
$tokenizer = new Tokenizer_Old('TestFile.php');
$tokens = $tokenizer->getTokens();
$vulnerable = array();
//print tokens here
foreach ($tokens as $token) {
    if ($token[0] == 397){
        continue;
    }
    if ($token[0] == 319){
        $vulnerable[] = $token;
    }
    echo "Token text => " . " " . $token[1]. "  Token id => " . $token[0] . " Token name => " . token_name($token[0]) . " line: ". $token[2] . " pos: " . $token[2] ."<br>";
}
echo "<br>";
?>