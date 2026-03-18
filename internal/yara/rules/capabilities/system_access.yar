rule PrivilegeEscalation {
    meta:
        description = "Detects privilege escalation attempts"
        severity = "critical"
        category = "capability"
    strings:
        $sudo = "sudo" nocase
        $su = "su " nocase
        $chown = "chown" nocase
        $setuid = "setuid" nocase
        $capability = "CAP_" nocase
    condition:
        any of them
}

rule KernelModule {
    meta:
        description = "Detects kernel module loading"
        severity = "critical"
        category = "capability"
    strings:
        $insmod = "insmod" nocase
        $rmmod = "rmmod" nocase
        $modprobe = "modprobe" nocase
        $kmod = "kmod" nocase
    condition:
        any of them
}
