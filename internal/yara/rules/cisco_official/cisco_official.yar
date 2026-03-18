rule Cisco_Official_Signature_Base {
    meta:
        description = "Assinatura base para conformidade Cisco"
        author = "Headmaster"
    strings:
        $s1 = "cisco_skill_scanner"
    condition:
        $s1
}
