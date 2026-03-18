rule System_Execution_Risk {
	meta:
		category = "system"
	strings:
		$s1 = "exec"
		$s2 = "syscall"
	condition:
		any of them
}
