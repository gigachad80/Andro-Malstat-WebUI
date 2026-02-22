rule Suspicious_Banker_Overlay {
    meta:
        description = "Detects overlay attacks common in banking trojans"
        severity = "High"
    strings:
        $a = "WindowManager$LayoutParams"
        $b = "SYSTEM_ALERT_WINDOW"
        $c = "setTitle"
        $d = "TYPE_APPLICATION_OVERLAY"
        $e = "canDrawOverlays"
    condition:
        3 of them
}