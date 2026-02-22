rule Crypto_Miner {
    meta:
        description = "Detects hidden crypto mining libraries"
        severity = "High"
    strings:
        $a = "stratum+tcp"
        $b = "minergate"
        $c = "monero"
        $d = "xmrig"
        $e = "cpuminer"
    condition:
        any of them
}
