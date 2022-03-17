<?php
    // code source de user.php
    $host = "localhost";
    $user_mysql = "root";     // nom d'utilisateur de l'utilisateur de MySQL 
    $password_mysql = "";     // mot de passe de l'utilisateur de MySQL
    $database = "db";

    $db = mysqli_connect($host, $user_mysql, $password_mysql, $database);
    mysqli_set_charset($db, "utf8");
?>

<!DOCTYPE html>
<html lang="fr">
    <head>
        <title></title>
        <meta charset="UTF-8" />
    </head>
    <body>
        <?php
            if(!empty($_POST['username']))
            {
                $user = mysqli_real_escape_string($db, $_POST['username']);
                $query = "SELECT username FROM users WHERE password LIKE '".$_POST['password']."';";
                $result = mysqli_query($db, $query);

                if(mysqli_num_rows($result) == 1)
                {
                    echo "<p>Utilisateur existant.</p>";
                }
                else
                {
                    echo "<p>Utilisateur inexistant.</p>";
                }
            }
        ?>
    </body>
</html>
