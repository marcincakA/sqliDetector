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
// Execute the query
$stmt3 = $pdo->query("SELECT * FROM users WHERE user_id=$unsafeUserId");

