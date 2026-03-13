rule Base64_Encoded_Execution {
    meta:
        description = "Detecta execução de código ofuscado em Base64"
        severity = "CRITICAL"
    strings:
        $b64_decode = /base64\.b64decode\(.*\)\.decode\(\)/
        $eval = "eval("
    condition:
        $b64_decode and $eval
}

rule Reverse_Shell_Pattern {
    meta:
        description = "Detecta padrões de Reverse Shell comuns"
        severity = "CRITICAL"
    strings:
        $python_rs = "pty.spawn(\"/bin/bash\")"
        $bash_rs = "/dev/tcp/"
    condition:
        any of them
}
