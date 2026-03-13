rule Network_Socket_Usage {
    meta:
        description = "Detecta criação de sockets de rede"
    strings:
        $socket = "socket.socket"
        $connect = ".connect(("
        $requests = /requests\.(get|post|put|delete)/
    condition:
        any of them
}
