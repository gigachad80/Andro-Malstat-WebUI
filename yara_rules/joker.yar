rule Joker_Billing_Fraud {
    meta:
        description = "Detects Joker/Bread WAP Billing Fraud"
        severity = "High"
    strings:
        $a = "NotificationListenerService"
        $b = "cancelAllNotifications"
        $c = "dcc" fullword // Obfuscated C2
        $d = "billing" nocase
        $e = "onNotificationPosted"
    condition:
        $a and ($b or $e) and ($c or $d)
}