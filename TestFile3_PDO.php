<?php

// Database credentials
$host = 'localhost';
$dbname = 'your_database';
$username = 'your_username';
$password = 'your_password';

$pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$unsafeUserId = $_GET['user_id']; // Assume this is coming from user input
$unsafeUserInput2 = $_GET['user_id2'];
//$pdo->quote($unsafeUserId);
$q = "SELECT * FROM users WHERE user_id = $unsafeUserId";
$q .= "AND user_id=". $unsafeUserId;
$q2 = "SELECT * FROM users WHERE user_id = $unsafeUserId";
$q2 .= "AND user_id= $unsafeUserInput2";
// Execute the query
$stmt = $pdo->query($q);
$stmt2 = $pdo->query($q2);
$stmt3 = $pdo->query("SELECT * FROM users WHERE user_id = $unsafeUserId");


