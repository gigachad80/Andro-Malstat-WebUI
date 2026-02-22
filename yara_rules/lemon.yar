rule Lemon_RAT {
    meta:
        description = "Detects L3MON / Lemon RAT"
        severity = "High"
    strings:
        $a = "L3MON" nocase
        $b = "Lemon" fullword
        $c = "gps_logging"
        $d = "live_clipboard"
        $e = "mw_main"
    condition:
        $a or 3 of them
}