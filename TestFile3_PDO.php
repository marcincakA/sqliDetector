<?php

// Database credentials
$host = 'localhost';
$dbname = 'your_database';
$username = 'your_username';
$password = 'your_password';

try {
    // Create a connection to the database using PDO
    $pdo = new PDO("mysql:host=$host;dbname=$dbname", $username, $password);

    // Set PDO to throw exceptions on errors
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

    // WARNING: Below is an unsafe way to construct a SQL query string using user input
    // This is highly vulnerable to SQL injection attacks
    // DO NOT USE THIS IN PRODUCTION CODE

    $quote = $unsafeUserId;

    $unsafeUserId = $_GET['user_id']; // Assume this is coming from user input
    //$pdo->quote($unsafeUserId);
    $q = "SELECT * FROM users WHERE user_id = $unsafeUserId";
    $q .= "AND user_id=". $unsafeUserId;
    $q2 = "SELECT * FROM users WHERE user_id = ".$unsafeUserId;
    $q2 .= "AND user_id=". $unsafeUserId;
    // Execute the query
    $stmt = $pdo->query($q);

    // Fetch the results
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    // Output the results
    print_r($user);

} catch (PDOException $e) {
    // Handle any errors that occur during the execution of the PDO object
    echo "Error: " . $e->getMessage();
}

