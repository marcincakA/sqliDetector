<?php
class Database {
    private $connection;

    public function __construct($host, $username, $password, $database) {
        $this->connection = mysqli_connect($host, $username, $password, $database);

        if (mysqli_connect_errno()) {
            throw new Exception("Failed to connect to MySQL: " . mysqli_connect_error());
        }
    }

    public function query($sql) {
        $result = mysqli_query($this->connection, $sql);

        if (!$result) {
            throw new Exception("Query failed: " . mysqli_error($this->connection));
        }

        return $result;
    }
}

// Example of usage with unsafe query
$database = new Database("localhost", "root", "", "shop");

$id = $_GET['id'];
$query = "SELECT * FROM products WHERE id=$id";

try {
    $result = $database->query($query);

    // Fetch data and do something with it
} catch (Exception $e) {
    echo $e->getMessage();
}
