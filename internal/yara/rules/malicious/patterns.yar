rule Generic_Malicious_Pattern {
	meta:
		severity = "high"
	strings:
		$p1 = "eval(base64_decode"
		$p2 = "powershell -enc"
	condition:
		any of them
}
