<?php

require_once 'flight/Flight.php';


/**** CONEXIÓN BD ****/

$host = $_ENV['DATABASE_HOST'];
$name = $_ENV['DATABASE_NAME'];
$user = $_ENV['DATABASE_USER'];
$pass = $_ENV['DATABASE_PASSWORD'];

Flight::register('db', 'PDO', array("mysql:host=$host;dbname=$name", $user, $pass));


/**** Middlewares ****/

class TokenMiddleware {
    public function before($params) {
        $token = Flight::request()->getHeader('X-Token');
        $datos = null;
        if (!empty($token))
        {
            $sql = 'SELECT * FROM usuarios WHERE token = ?';
            $sentencia = Flight::db()->prepare($sql);
            $sentencia->bindParam(1, $token);
            $sentencia->execute();
            $datos = $sentencia->fetch();
        }

        if ($datos == null)
        {
            Flight::jsonHalt(['error' => "Token no válido."], 403);
            exit;
        }
        else
        {
            Flight::set('user', $datos);
        }
        
    }
}

class ContactoMiddleware {
    public function before($params) {
        $id = Flight::request()->data->id;
        $usuario = Flight::get('user');
        if ($id && $usuario)
        {
            $sql = 'SELECT id FROM contactos WHERE id = ? AND usuario_id = ?';
            $sentencia = Flight::db()->prepare($sql);
            $sentencia->bindParam(1, $id);
            $sentencia->bindParam(2, $usuario['id']);
            $sentencia->execute();
            $datos = $sentencia->fetch();
        }

        if (!$datos)
        {
            Flight::jsonHalt(['error' => "No existe el contacto solicitado."], 403);
            exit;
        }
        
    }
}

$tokenMiddleware = new TokenMiddleware();
$contactoMiddleware = new ContactoMiddleware();


/**** Rutas ****/

Flight::route('/', function () {
    echo 'API AGENDA';
});

Flight::route('POST /register', function(){
    
    $nombre = Flight::request()->data->nombre;
    $email = Flight::request()->data->email;
    $password = Flight::request()->data->password;

    if (empty($nombre) || empty($email) || empty($password))
    {
        Flight::json(['error' => 'Todos los datos son obligatorios.'], 400);
        return;
    }
    
    $sql = 'SELECT id FROM usuarios where email = ?';
    $sentencia = Flight::db()->prepare($sql);
    $sentencia->bindParam(1, $email);
    $sentencia->execute();

    if ($sentencia->fetch())
    {
        Flight::json(['error' => "Usuario $email ya registrado."], 409);
        return;
    }

    $hash = password_hash($password, PASSWORD_DEFAULT);

    $sql = 'INSERT INTO usuarios(nombre, email, password) VALUES (?, ?, ?)';

    $sentencia = Flight::db()->prepare($sql);
    $sentencia->bindParam(1, $nombre);
    $sentencia->bindParam(2, $email);
    $sentencia->bindParam(3, $hash);

    if ($sentencia->execute())
    {
        Flight::json(['message' => 'Cliente guardado correctamente.']);
    }
    else
    {
        Flight::json(['error' => 'Error gestionando la petición.'], 500);
    }

});

Flight::route('POST /login', function(){
    
    $email = Flight::request()->data->email;
    $password = Flight::request()->data->password;

    $sql = 'SELECT id, password FROM usuarios where email = ?';
    $sentencia = Flight::db()->prepare($sql);
    $sentencia->bindParam(1, $email);
    $sentencia->execute();

    $datos = $sentencia->fetch();

    if ($datos && password_verify($password, $datos['password']))
    {
        $token = bin2hex(random_bytes(32));
        $id = $datos['id'];
        $sql = "UPDATE usuarios SET token=? WHERE id=?";
        $sentencia = Flight::db()->prepare($sql);
        $sentencia->bindParam(1, $token);
        $sentencia->bindParam(2, $id);
        $sentencia->execute();
        Flight::json([
            'message' => 'Autenticación correcta.',
            'token' => $token
        ]);
        return;
    }
    else
    {
        Flight::json(['error' => "Credenciales incorrectas."], 401);
        return;
    }
    
    Flight::json(['error' => 'Error gestionando la petición.'], 500);

});

Flight::route('GET /contactos(/@id)', function($id = null)
{
    if ($id)
    {
        $sentencia = Flight::db()->prepare("SELECT * FROM contactos WHERE id = :id AND usuario_id = :usuario");
        $sentencia->bindParam(':id', $id);
        $sentencia->bindParam(':usuario', Flight::get('user')['id']);
        $sentencia->execute();
        $datos = $sentencia->fetch();
        if (!$datos) $datos = [];
    }
    else
    {
        $sentencia = Flight::db()->prepare("SELECT * FROM contactos WHERE usuario_id = :usuario");
        $sentencia->bindParam(':usuario', Flight::get('user')['id']);
        $sentencia->execute();
        $datos = $sentencia->fetchAll();
    }
    Flight::json($datos);

})->addMiddleware($tokenMiddleware);

Flight::route('POST /contactos', function()
{
    $nombre = Flight::request()->data->nombre;
    $email = Flight::request()->data->email;
    $telefono = Flight::request()->data->telefono;

    $sql = 'INSERT INTO contactos(nombre, email, telefono, usuario_id) VALUES (?, ?, ?, ?)';

    $sentencia = Flight::db()->prepare($sql);
    $sentencia->bindParam(1, $nombre);
    $sentencia->bindParam(2, $email);
    $sentencia->bindParam(3, $telefono);
    $sentencia->bindParam(4, Flight::get('user')['id']);

    $sentencia->execute();

    Flight::json(['message'=> "Contacto $nombre guardado correctamente."]);

})->addMiddleware($tokenMiddleware);

Flight::route('PUT /contactos', function()
{
    $id = Flight::request()->data->id;
    $nombre = Flight::request()->data->nombre;
    $email = Flight::request()->data->email;
    $telefono = Flight::request()->data->telefono;

    $sql = "UPDATE contactos SET nombre=?, email=?, telefono=? WHERE id=?";
    $sentencia = Flight::db()->prepare($sql);
    $sentencia->bindParam(1, $nombre);
    $sentencia->bindParam(2, $email);
    $sentencia->bindParam(3, $telefono);
    $sentencia->bindParam(4, $id);

    $sentencia->execute();

    Flight::json(['message'=> "Contacto $nombre actualizado correctamente."]);
    
})->addMiddleware([$tokenMiddleware, $contactoMiddleware]);

Flight::route('DELETE /contactos', function(){
    $id = Flight::request()->data->id;

    $sql = 'DELETE FROM contactos WHERE id=:id';

    $sentencia = Flight::db()->prepare($sql);
    $sentencia->bindParam(':id', $id);

    $sentencia->execute();

    Flight::json(['message'=> "Contacto eliminado correctamente."]);

})->addMiddleware([$tokenMiddleware, $contactoMiddleware]);



/**** API START ****/

Flight::start();
