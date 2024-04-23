<?php

$id = $_GET['id'];
$query = "SELECT * FROM products WHERE id=$id";
$result = $database->query("SELECT * FROM products WHERE id=".$id);