rule Cypher_RAT {
    meta:
        description = "Detects Cypher RAT (SpyNote evolution)"
        severity = "Critical"
    strings:
        $a = "CypherRat" nocase
        $b = "crypto wallets" nocase
        $c = "client_id"
        $d = "trust_wallet"
        $e = "coinbase"
    condition:
        $a or ($c and 2 of ($b,$d,$e))
}