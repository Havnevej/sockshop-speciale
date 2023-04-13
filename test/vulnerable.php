<?php
// This is a vulnerable PHP file for testing remote shell execution in Kubernetes environment

// Read the command from GET parameter
$command = $_GET['command'];

// Perform some operation based on the input
if (isset($command)) {
    echo "Running command: " . $command . "<br>";
    echo "Result: ";
    // Execute the command using shell_exec
    $output = shell_exec($command);
    echo $output;
}
?>

<html>
<head>
    <title>Webpage</title>
</head>
<body>
    <h1>My Webpage</h1>
    <p>This webpage does some real work and displays the result below.</p>
    <hr>
    <form method="get" action="">
        <label for="command">Enter command:</label>
        <input type="text" name="command" id="command">
        <input type="submit" value="Execute">
    </form>
</body>
</html>
