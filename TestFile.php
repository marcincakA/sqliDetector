<?php
// Assume that $id is obtained from user input
$id = $_GET['id'];

// Vulnerable SQL query
$query = "SELECT * FROM products WHERE id=$id";

// Execute the query
$result = mysqli_query($connection, $query);

// Fetch the data
while ($row = mysqli_fetch_assoc($result)) {
    // Output product details
    echo "Product ID: " . $row['id'] . "<br>";
    echo "Product Name: " . $row['name'] . "<br>";
    echo "Product Price: $" . $row['price'] . "<br>";
}

// Close the connection
mysqli_close($connection);
?>