rule Anti_Analysis_Tools {
    meta:
        description = "Detects code trying to evade detection (Frida, Root)"
        severity = "Medium"
    strings:
        $a = "frida-server"
        $b = "com.noshufou.android.su"
        $c = "eu.chainfire.supersu"
        $d = "isDebuggerConnected"
        $e = "/system/bin/su"
    condition:
        2 of them
}c