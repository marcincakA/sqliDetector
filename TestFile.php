<?php
// Assume that $id is obtained from user input
$id = $_GET['id'];
$name = $_GET['name'];
// Vulnerable SQL query
$query = "SELECT * FROM products WHERE id=$id";
// Connect to the database
$connection = mysqli_connect("localhost", "root", "", "shop", "", "");
// Execute the query
mysqli_real_escape_string($connection, $id);

$result = mysqli_query($connection, $query);

// Fetch the data
while ($row = mysqli_fetch_assoc($result)) {
    // Output product details
    echo "Product ID: " . $row['id'] . "<br>";
    echo "Product Name: " . $row['name'] . "<br>";
    echo "Product Price: $" . $row['price'] . "<br>";
}
//escaped query riesenie 1
$query = "SELECT * FROM products WHERE id=" . mysqli_real_escape_string($connection, $id);
// Close the connection

$result2 = mysqli_query($connection, "SELECT * FROM products WHERE id=$id");
$result3 = mysqli_query($connection, "SELECT * FROM products WHERE id=$id", MYSQLI_STORE_RESULT);
$result3 = mysqli_query($connection, "SELECT * FROM products WHERE id=$id", 0);
mysqli_close($connection);

$query = "SELECT * FROM products WHERE id=$id AND name=$name";
$query = "SELECT * FROM products WHERE id=? AND name=?";

?>