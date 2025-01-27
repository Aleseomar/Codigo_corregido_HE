# \- `add_comment.php`

Este código permite al atacante inyectar código SQL.

- Inyección SQL:

```php
$query = "INSERT INTO comments (playerId, userId, body) VALUES ('".$_GET['id']."', '".$_COOKIE['userId']."', '$body')";
```

Usaremos `prepared statements` para prevenir de estas inyecciones SQL.

```
$stmt = $db->prepare("INSERT INTO comments (playerId, userId, body) VALUES (:playerId, :userId, :body)");
$stmt->bindValue(':playerId', $_GET['id'], SQLITE3_INTEGER);
$stmt->bindValue(':userId', $_COOKIE['userId'], SQLITE3_INTEGER);
$stmt->bindValue(':body', $body, SQLITE3_TEXT);
$stmt->execute();

```

- XSS

Usaremos el parámetro `htmlspecialchars()` para limpiar la entrada del usuario de caracteres especiales como >, < , ', ". Así evitaremos ataques XSS.

```php
echo htmlspecialchars($row['body'], ENT_QUOTES, 'UTF-8');
```

- Código corregido

```php
<?php
require_once dirname(__FILE__) . '/private/conf.php';

# Require logged users
require dirname(__FILE__) . '/private/auth.php';

if (isset($_POST['body']) && isset($_GET['id'])) {
    # Just in from POST => save to database
    $body = $_POST['body'];
    
    ## Sanitizamos el contenido del body para evitar XSS. 
    $body = htmlspecialchars($body, ENT_QUOTES, 'UTF-8'); 

    ## Evitamos la inyección SQL con prepare
    $stmt = $db->prepare("INSERT INTO comments (playerId, userId, body) VALUES (:playerId, :userId, :body)");
    $stmt->bindValue(':playerId', $_GET['id'], SQLITE3_INTEGER);
    $stmt->bindValue(':userId', $_COOKIE['userId'], SQLITE3_INTEGER);
    $stmt->bindValue(':body', $body, SQLITE3_TEXT);
    $stmt->execute();
    
    header("Location: list_players.php");   
}
?>


<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="css/style.css">
    <title>Práctica RA3 - Comments creator</title>
</head>
<body>
<header>
    <h1>Comments creator</h1>
</header>
<main class="player">
    <form action="#" method="post">
        <h3>Write your comment</h3>
        <textarea name="body"></textarea>
        <input type="submit" value="Send">
    </form>
    <form action="#" method="post" class="menu-form">
        <a href="list_players.php">Back to list</a>
        <input type="submit" name="Logout" value="Logout" class="logout">
    </form>
</main>
<footer class="listado">
    <img src="images/logo-iesra-cadiz-color-blanco.png">
    <h4>Puesta en producción segura</h4>
    < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
</footer>
</body>
</html>
```

* * *

# \- `buscador.php`

- SQL

Haremos exactamente lo mismo en el código,

```php
$name = $_GET['name'];
$query = "SELECT playerid, name, team FROM players where name='$name' order by playerId desc ";
```

usaremos `prepared statements` para prevenir de estas inyecciones SQL.

```php
$name = $_GET['name'];
$stmt = $db->prepare("SELECT playerid, name, team FROM players WHERE name = :name ORDER BY playerId DESC");
$stmt->bindValue(':name', $name, SQLITE3_TEXT);
$result = $stmt->execute();
```

- Código corregido

```php
<?php
    require_once dirname(__FILE__) . '/private/conf.php';

    # Require logged users
    require dirname(__FILE__) . '/private/auth.php';
    
    # EVITAMOS INYECCIÓN SQL 
    $name = $_GET['name'];
    $stmt = $db->prepare("SELECT playerid, name, team FROM players WHERE name = :name ORDER BY playerId DESC");
    $stmt->bindValue(':name', $name, SQLITE3_TEXT);
    $result = $stmt->execute();

    $result = $db->query($query) or die("Invalid query");
?>


<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="css/style.css">
    <title>Práctica RA3 - Búsqueda</title>
</head>
<body>
    <header class="listado">
        <h1>Búsqueda de <? echo $name ?></h1>
    </header>
    <main class="listado">
        <ul>
        <?php
        while ($row = $result->fetchArray()) {
            echo "
                <li>
                <div>
                <span>Name: " . $row['name']
                . "</span><span>Team: " . $row['team']
                . "</span></div>
                <div>
                <a href=\"show_comments.php?id=".$row['playerid']."\">(show/add comments)</a> 
                <a href=\"insert_player.php?id=".$row['playerid']."\">(edit player)</a>
                </div>
                </li>\n";
        }
        ?>
        </ul>
        <form action="#" method="post" class="menu-form">
            <a href="index.php">Back to home</a>
            <a href="list_players.php">Back to list</a>
            <input type="submit" name="Logout" value="Logout" class="logout">
        </form>

        </main>
        <footer class="listado">
            <img src="images/logo-iesra-cadiz-color-blanco.png">
            <h4>Puesta en producción segura</h4>
            < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
        </footer>
    </body>
</html>

```

* * *



# \- `insert_player.php`

- XSS

Sanitizamos la entrada de name y team antes de validarlo.

```php
$name = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
$team = htmlspecialchars($team, ENT_QUOTES, 'UTF-8');
```

- SQL

Protegemos ante inyección SQL

```php
if (isset($_GET['id']))
    $query = "INSERT OR REPLACE INTO players (playerid, name, team) VALUES ('".$_GET['id']."','$name', '$team')";
else
    $query = "INSERT INTO players (name, team) VALUES ('$name', '$team')";
$db->query($query) or die("Invalid query");
```

con el prepare:

```php
if (isset($_GET['id'])) {
    $stmt = $db->prepare("INSERT OR REPLACE INTO players (playerid, name, team) VALUES (?, ?, ?)");
    $stmt->bind_param('iss', $_GET['id'], $name, $team);
} else {
    $stmt = $db->prepare("INSERT INTO players (name, team) VALUES (?, ?)");
    $stmt->bind_param('ss', $name, $team);
}

$stmt->execute() or die("Invalid query");
```

- Código corregido

```php
<?php
require_once dirname(__FILE__) . '/private/conf.php';

# Require logged users
require dirname(__FILE__) . '/private/auth.php';

if (isset($_POST['name']) && isset($_POST['team'])) {
    # Just in from POST => save to database
    $name = $_POST['name'];
    $team = $_POST['team'];

    # Sanitize inputs
    $name = htmlspecialchars($name, ENT_QUOTES, 'UTF-8');
    $team = htmlspecialchars($team, ENT_QUOTES, 'UTF-8');

    // Protegemos contra inyección SQL
    if (isset($_GET['id'])) {
        $stmt = $db->prepare("INSERT OR REPLACE INTO players (playerid, name, team) VALUES (?, ?, ?)");
        $stmt->bind_param('iss', $_GET['id'], $name, $team);
    } else {
        $stmt = $db->prepare("INSERT INTO players (name, team) VALUES (?, ?)");
        $stmt->bind_param('ss', $name, $team);
    }

    $stmt->execute() or die("Invalid query");
    
} else {
    # Show info to modify
    if (isset($_GET['id'])) {
        # Edit from database
        $id = $_GET['id'];

        $stmt = $db->prepare("SELECT name, team FROM players WHERE playerid = ?");
        $stmt->bind_param('i', $id);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result->fetch_assoc() or die ("modifying a nonexistent player!");

        $name = $row['name'];
        $team = $row['team'];
    }
}

# Show form

?>
<!doctype html>
<html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport"
              content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="ie=edge">
        <link rel="stylesheet" href="css/style.css">
        <title>Práctica RA3 - Players list</title>
    </head>
    <body>
        <header>
            <h1>Player</h1>
        </header>
        <main class="player">
            <form action="#" method="post">
                <input type="hidden" name="id" value="<?=$id?>"><br>
                <h3>Player name</h3>
                <textarea name="name"><?=$name?></textarea><br>
                <h3>Team name</h3>
                <textarea name="team"><?$team?></textarea><br>
                <input type="submit" value="Send">
            </form>
            <form action="#" method="post" class="menu-form">
                <a href="index.php">Back to home</a>
                <a href="list_players.php">Back to list</a>
                <input type="submit" name="Logout" value="Logout" class="logout">
            </form>
        </main>
        <footer class="listado">
            <img src="images/logo-iesra-cadiz-color-blanco.png">
            <h4>Puesta en producción segura</h4>
            < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
        </footer>
    </body>
</html>


```

* * *


# \- `register.php`

- Hash de contraseñas

El almacenamiento de las contraseñas no es seguro.

```php
$password = SQLite3::escapeString($password);
```

Tendremos que crear una función para hashear esas contraseñas.

```php
$hashed_password = password_hash($password, PASSWORD_DEFAULT);
```

- SQL

Protegemos contra inyección SQL

```php
$query = "INSERT INTO users (username, password) VALUES ('$username', '$password')";
```

y lo transformamos:

```php
# Evitamos inyección SQL
$stmt = $db->prepare('INSERT INTO users (username, password) VALUES (:username, :password)');
$stmt->bindValue(':username', $username, SQLITE3_TEXT);
$stmt->bindValue(':password', $hashed_password, SQLITE3_TEXT);
```

- Código corregido

```php
<?php
require_once dirname(__FILE__) . '/private/conf.php';

# Require logged users
# require dirname(__FILE__) . '/private/auth.php';

if (isset($_POST['username']) && isset($_POST['password'])) {
    # Just in from POST => save to database
    $username = $_POST['username'];
    $password = $_POST['password'];
    
    # Función para hashear la contraseña
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);
    
    # Evitamos inyección SQL
    $stmt = $db->prepare('INSERT INTO users (username, password) VALUES (:username, :password)');
    $stmt->bindValue(':username', $username, SQLITE3_TEXT);
    $stmt->bindValue(':password', $hashed_password, SQLITE3_TEXT);

    $db->query($query) or die("Invalid query");
    header("Location: list_players.php");
}

# Show form

?>
<!doctype html>
<html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport"
              content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="ie=edge">
        <link rel="stylesheet" href="css/style.css">
        <title>Práctica RA3 - Players list</title>
    </head>
    <body>
        <header>
            <h1>Register</h1>
        </header>
        <main class="player">
            <form action="#" method="post">
                <input type="hidden" name="id" value="<?=$id?>">
                <label>Username:</label>
                <input type="text" name="username">
                <label>Password:</label>
                <input type="password" name="password">
                <input type="submit" value="Send">
            </form>
                <form action="#" method="post" class="menu-form">
                <a href="list_players.php">Back to list</a>
                <input type="submit" name="Logout" value="Logout" class="logout">
            </form>
        </main>
        <footer class="listado">
            <img src="images/logo-iesra-cadiz-color-blanco.png">
            <h4>Puesta en producción segura</h4>
            < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
        </footer>
    </body>
</html>
```

* * *


# \- `show_comments.php`

- XSS

Utilizaremos `htmlspecialchars` para sanitizar la salida de los comentarios.

```php
$username = htmlspecialchars($row['username'], ENT_QUOTES, 'UTF-8');
$body = htmlspecialchars($row['body'], ENT_QUOTES, 'UTF-8');
```

- SQL

Utilizaremos prepare para evitar inyección SQL.

```php
$query = "SELECT commentId, username, body FROM comments C, users U WHERE C.playerId =".$_GET['id']." AND U.userId = C.userId order by C.playerId desc";
$result = $db->query($query) or die("Invalid query: " . $query );
```

Y lo pasamos a:

```php
$playerId = $_GET['id'];
$stmt = $db->prepare("SELECT commentId, username, body FROM comments C, users U WHERE C.playerId = :playerId AND U.userId = C.userId ORDER BY C.playerId DESC");
$stmt->bindValue(':playerId', $playerId, SQLITE3_INTEGER);
$result = $stmt->execute() or die("Invalid query");
```

- Código corregido

```php
<?php
require_once dirname(__FILE__) . '/private/conf.php';

# Require logged users
require dirname(__FILE__) . '/private/auth.php';
?>
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="css/style.css">
    <title>Práctica RA3 - Comments editor</title>
</head>
<body>
<header>
    <h1>Comments editor</h1>
</header>
<main class="player">

<?php
require_once dirname(__FILE__) . '/private/conf.php';

# Require logged users
#require dirname(__FILE__) . '/private/auth.php';

# List comments
if (isset($_GET['id']))
{
    $playerId = $_GET['id'];
    $stmt = $db->prepare("SELECT commentId, username, body FROM comments C, users U WHERE C.playerId = :playerId AND U.userId = C.userId ORDER BY C.playerId DESC");
    $stmt->bindValue(':playerId', $playerId, SQLITE3_INTEGER);

    $result = $stmt->execute() or die("Invalid query");

    while ($row = $result->fetchArray()) {
        $username = htmlspecialchars($row['username'], ENT_QUOTES, 'UTF-8');
        $body = htmlspecialchars($row['body'], ENT_QUOTES, 'UTF-8');
        echo "<div>
                <h4> ". $username ."</h4> 
                <p>commented: " . $body . "</p>
              </div>";
    }
}

# Show form

?>

<div>
    <a href="list_players.php">Back to list</a>
    <a class="black" href="add_comment.php?id=<?php echo $playerId;?>"> Add comment</a>
</div>

</main>
<footer class="listado">
    <img src="images/logo-iesra-cadiz-color-blanco.png">
    <h4>Puesta en producción segura</h4>
    < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
</footer>
</body>
</html>


```

* * *


# \- `index.php`

- Token CSRF

No encontramos opciones de seguridad en la parte de las cookies por lo que hemos pensado en añadirle más seguridad. Para ello hemos creado una función al principio del formulario donde agregará un token y lo verificará que este activo y sea correcto.

```php
session_start();

# Generar un token si no tenemos o no existe
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
# On logout
if (isset($_POST['Logout'])) {
    # Verificar que el token este presente
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die('El token csrf es inválido o no está presente');
    }
```

- Código corregido

```php
<?php
# On logout
session_start();

# Generar un token si no tenemos o no existe
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
# On logout
if (isset($_POST['Logout'])) {
    # Verificar que el token este presente
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die('El token csrf es inválido o no está presente');
    }

    # Delete cookies
    setcookie('user', FALSE);
    setcookie('password', FALSE);
    setcookie('userId', FALSE);

    unset($_COOKIE['user']);
    unset($_COOKIE['password']);
    unset($_COOKIE['userId']);

    header("Location: index.php");
}
?>
<!doctype html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport"
          content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <link rel="stylesheet" href="css/style.css">
    <title>Práctica RA3</title>
</head>
<body>
    <header>
        <h1>Developers Awards</h1>
    </header>
    <main>
        <h2><a href="insert_player.php"> Add a new player</a></h2>
        <h2><a href="list_players.php"> List of players</a></h2>
        <h2><a href="buscador.html"> Search a player</a></h2>

    </main>
    <form action="#" method="post" class="menu-form">
        <input type="submit" name="Logout" value="Logout" class="logout">
    </form>
    <footer>
        <h4>Puesta en producción segura</h4>
        < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
    </footer>
</body>
</html>

```

* * *

# \- `auth.php`

- SQL

Evitaremos la inyección SQL en el siguiente código:

```php
$query = SQLite3::escapeString('SELECT userId, password FROM users WHERE username = "' . $user . '"');
$result = $db->query($query) or die ("Invalid query: " . $query . ". Field user introduced is: " . $user);
$row = $result->fetchArray();
```

Modificaremos con el uso del `prepare`:

```php
$stmt = $db->prepare('SELECT userId, password FROM users WHERE username = :username');
$stmt->bindValue(':username', $user, SQLITE3_TEXT);

$result = $stmt->execute() or die ("Invalid query");
$row = $result->fetchArray();
```

- Contraseña

Cambiaremos el código de verificación de la contraseña.

```php
if(!isset($row['password'])) return FALSE;
    //print($row);
if ($password == $row['password'])
{
    $userId = $row['userId'];
    $_COOKIE['userId'] = $userId;
    return TRUE;
}
else {
    return FALSE;
}
```

Nosotros utilizaremos la función `password_verify` para comprobar la contraseña hasheada.

```php
if(!isset($row['password'])) return FALSE;

if (password_verify($password, $row['password'])) {
    $userId = $row['userId'];
    $_COOKIE['userId'] = $userId;
    return TRUE;
} else {
    return FALSE;
}
```

- Código corregido

```php
<?php
require_once dirname(__FILE__) . '/conf.php';

$userId = FALSE;

# Check whether a pair of user and password are valid; returns true if valid.
function areUserAndPasswordValid($user, $password) {
    global $db, $userId;

    $stmt = $db->prepare('SELECT userId, password FROM users WHERE username = :username');
    $stmt->bindValue(':username', $user, SQLITE3_TEXT);

    $result = $stmt->execute() or die ("Invalid query");
    $row = $result->fetchArray();

    if(!isset($row['password'])) return FALSE;

    if (password_verify($password, $row['password'])) {
        $userId = $row['userId'];
        $_COOKIE['userId'] = $userId;
        return TRUE;
    } else {
        return FALSE;
    }
}

# On login
if (isset($_POST['username'])) {		
    $_COOKIE['user'] = $_POST['username'];
    if(isset($_POST['password']))
        $_COOKIE['password'] = $_POST['password'];
    else
        $_COOKIE['password'] = "";
} else {
    if (!isset($_POST['Logout']) && !isset($_COOKIE['user'])) {
        $_COOKIE['user'] = "";
        $_COOKIE['password'] = "";
    }
}

# On logout
if (isset($_POST['Logout'])) {
    # Delete cookies
    setcookie('user', FALSE);
    setcookie('password', FALSE);
    setcookie('userId', FALSE);
    
    unset($_COOKIE['user']);
    unset($_COOKIE['password']);
    unset($_COOKIE['userId']);

    header("Location: index.php");
}


# Check user and password
if (isset($_COOKIE['user']) && isset($_COOKIE['password'])) {
    if (areUserAndPasswordValid($_COOKIE['user'], $_COOKIE['password'])) {
        $login_ok = TRUE;
        $error = "";
    } else {
        $login_ok = FALSE;
        $error = "Invalid user or password.<br>";
    }
} else {
    $login_ok = FALSE;
    $error = "This page requires you to be logged in.<br>";
}

if ($login_ok == FALSE) {

?>
    <!doctype html>
    <html lang="es">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport"
              content="width=device-width, user-scalable=no, initial-scale=1.0, maximum-scale=1.0, minimum-scale=1.0">
        <meta http-equiv="X-UA-Compatible" content="ie=edge">
        <link rel="stylesheet" href="css/style.css">
        <title>Práctica RA3 - Authentication page</title>
    </head>
    <body>
    <header class="auth">
        <h1>Authentication page</h1>
    </header>
    <section class="auth">
        <div class="message">
            <?= $error ?>
        </div>
        <section>
            <div>
                <h2>Login</h2>
                <form action="#" method="post">
                    <label>User</label>
                    <input type="text" name="username"><br>
                    <label>Password</label>
                    <input type="password" name="password"><br>
                    <input type="submit" value="Login">
                </form>
            </div>

            <div>
                <h2>Logout</h2>
                <form action="#" method="post">
                    <input type="submit" name="Logout" value="Logout">
            </div>
        </section>
    </section>
    <footer>
        <h4>Puesta en producción segura</h4>
        < Please <a href="http://www.donate.co?amount=100&amp;destination=ACMEScouting/"> donate</a> >
    </footer>
    <?php
    exit (0);
}

setcookie('user', $_COOKIE['user']);
setcookie('password', $_COOKIE['password']);


?>

```
