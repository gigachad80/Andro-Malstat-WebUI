rule CraxsRAT {
    meta:
        description = "Detects CraxsRAT / SpyMax (EVLF Dev)"
        severity = "Critical"
    strings:
        $a = "CraxsRat" nocase
        $b = "EVLF"
        $c = "SpyMax"
        $d = "receivers.Service"
        $e = "MyReceiver"
        $f = "craxs" nocase
    condition:
        2 of them
}




