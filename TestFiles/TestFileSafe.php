<?php
// Assume that $id is obtained from user input
//$id = $_GET['id'];
$id = $_GET['id'];
$name = $_GET['name'];
$age = $_GET['name'];
$connection = mysqli_connect("localhost", "root", "", "shop", "", "");
mysqli_real_escape_string($connection, $name);
mysqli_real_escape_string($connection, $id);
$q = "SELECT * FROM products WHERE id = $id";
$result3 = mysqli_query($connection, $q);
mysqli_close($connection);


?>