<?php
// Assume that $id is obtained from user input
//$id = $_GET['id'];
$id = readline("Enter id: ");
$name = $_GET['name'];
$age = $_GET['name'];
$connection = mysqli_connect("localhost", "root", "", "shop", "", "");

//id nebude zranitelne lebo je v escape_string pred zostrojenim query
//mysqli_real_escape_string($connection, $id);
//mysqli_real_escape_string($connection, $name);
// Vulnerable SQL query
//$qr = "SELECT * FROM products WHERE id=$id";
// Connect to the database

// Execute the query


//$result = mysqli_query($connection, $qr);

//escaped query riesenie 1

//$qry = "SELECT * FROM products WHERE id=" . mysqli_real_escape_string($connection, $id);
//$qry = "SELECT * FROM products WHERE id=$id"; //. "And id=". $name;
//$qry .= "AND id=". $name;

mysqli_real_escape_string($connection, $name);

//$result2 = mysqli_query($connection, "SELECT * FROM products WHERE id=$id");
//$result2 = mysqli_query($connection, "SELECT * FROM products WHERE id=$age");
$result3 = mysqli_query($connection, "SELECT * FROM products WHERE id=".$id);
//$result3 = mysqli_query($connection, "SELECT * FROM products WHERE id=$name", 0);
mysqli_close($connection);


?>