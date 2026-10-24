<?php
// Deliberately unsafe training example. Do not deploy.
$page = $_GET['page'] ?? 'home';
include($page . '.php');
$query = "SELECT * FROM users WHERE name = '" . $_GET['name'] . "'";
eval($_POST['expression']);
