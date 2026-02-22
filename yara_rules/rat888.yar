rule RAT_888 {
    meta:
        description = "Detects 888 RAT - Commercial Android Trojan"
        severity = "High"
    strings:
        $a = "888 RAT" nocase
        $b = "com.example.dat.a8andoserverx"
        $c = "screencap"
        $d = "boot_completed"
    condition:
        $b or 2 of them
}