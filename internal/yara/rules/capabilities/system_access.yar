rule Suspect_Process_Execution {
    meta:
        description = "Detecta execução de comandos de sistema em scripts"
        severity = "MEDIUM"
    strings:
        $python_os = /os\.(system|popen|spawn)/
        $python_sub = /subprocess\.(run|Popen|call)/
        $node_child = /child_process\.(exec|spawn)/
    condition:
        any of them
}

rule Network_Socket_Opening {
    meta:
        description = "Detecta abertura de sockets de rede"
        severity = "HIGH"
    strings:
        $socket = "socket.socket"
        $http_req = /requests\.(get|post|put|delete)/
        $urllib = "urllib.request"
    condition:
        any of them
}
