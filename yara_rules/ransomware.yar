rule Ransomware_Indicators {
    meta:
        description = "Detects common ransomware terminology"
        severity = "Critical"
    strings:
        $a = "decrypt" nocase
        $b = "locked" nocase
        $c = "tor browser" nocase
        $d = ".onion"
        $e = "bitcoin" nocase
        $f = "AES/ECB"
    condition:
        3 of them
}