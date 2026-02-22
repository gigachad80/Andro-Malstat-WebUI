rule Venom_Metasploit_Wrapper {
    meta:
        description = "Detects Venom (Shellcode Wrapper) & Metasploit Payloads"
        severity = "Critical"
    strings:
        $msf1 = "com.metasploit.stage"
        $msf2 = "payload.bin"
        $msf3 = "meterpreter"
        $msf4 = "PayloadTrustManager"
        $venom1 = "venom" nocase
        $venom2 = "shellcode"
        $venom3 = "/bin/sh"
    condition:
        (any of ($msf*)) or (2 of ($venom*))
}