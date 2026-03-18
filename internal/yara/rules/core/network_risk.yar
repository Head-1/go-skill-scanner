rule Network_Socket_Usage {
	meta:
		category = "network"
	strings:
		$s1 = "socket"
		$s2 = "connect"
	condition:
		any of them
}
