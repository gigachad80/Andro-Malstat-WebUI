rule ClayRat_Spyware {
    meta:
        description = "Detects ClayRat - Targeted Russian Spyware"
        severity = "Critical"
    strings:
        $a = "apezdolskynet"
        $b = "ClayRemoteDesktop"
        $c = "turbo_screen"
        $d = "lock_password_storage"
    condition:
        any of them
}