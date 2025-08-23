<?php
$conn = mysqli_connect("localhost", "vulnuser", "vulnpassword", "vulnsite"); // Uses the vulnuser account made in the SQL database to avoid any problems with root

if (!$conn) {
    die("Connection failed: " . mysqli_connect_error()); // If connection fails
}

if (isset($_POST['username']) && isset($_POST['password'])) {

    $username = $_POST['username'];
    $password = $_POST['password'];

    $sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'"; // Parameters go directly into database query, creating unsafe input

    $result = mysqli_query($conn, $sql);

    if (mysqli_num_rows($result) > 0) {
        echo "Welcome, " . $username . "!";
    } else {
        echo "Invalid username or password."; // Error message used in hydra command
    }
}
?>
<!--HTML portion(how the website will look)-->
<!DOCTYPE html> 
<html>
<head>
    <title>Vulnerable Login</title>
</head>
<body>
    <h1>Login</h1>
    <form method="POST" action="">
        Username: <input type="text" name="username"><br>
        Password: <input type="text" name="password"><br>
        <input type="submit" value="Login">
    </form>
</body>
</html>
