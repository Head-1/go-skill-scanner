rule Coverage_Test_Rule {
    meta:
        description = "Regra para validar testes de cobertura"
        severity = "low"
    strings:
        $target = "GSS_TEST_PAYLOAD_STRICT"
    condition:
        $target
}
