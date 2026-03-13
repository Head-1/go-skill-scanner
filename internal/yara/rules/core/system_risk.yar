rule Suspect_Execution_Pattern {
    meta:
        description = "Detecta chamadas de execução de sistema em scripts"
        author = "Go-Skill-Scanner-Core"
    strings:
        // Padrões genéricos de execução que o motor Go deve barrar
        $cmd_exec = /os\.(system|popen|spawn)/
        $sub_proc = /subprocess\.(run|Popen|call)/
        $shell_exec = /exec\(.*\)/
    condition:
        any of them
}

rule Destructive_Commands {
    meta:
        description = "Detecta comandos destrutivos de sistema"
    strings:
        $rm_rf = "rm -rf /"
        $shred = "shred"
        $mkfs = "mkfs"
    condition:
        any of them
}
