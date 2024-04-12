<?php

$id = $_GET['id'];
//mysqli_real_escape_string($database->connection, $id);
$query = "SELECT * FROM products WHERE id=$id";
try {
    $result = $database->query("SELECT * FROM products WHERE id=".mysqli_real_escape_string($id));

    // Fetch data and do something with it
} catch (Exception $e) {
    echo $e->getMessage();
}
