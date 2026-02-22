rule SpyNote_Generic {
    meta:
        description = "Detects SpyNote variants"
        severity = "Critical"
    strings:
        $a = "SERVER_IP"
        $b = "content://sms/inbox"
        $c = "smarter"
        $d = "screencap"
        $e = "BootComplete"
    condition:
        3 of them
}