rule Dropper_Payload {
    meta:
        description = "Detects hidden APKs inside assets (Loader)"
        severity = "High"
    strings:
        $a = "assets/"
        $b = ".apk"
        $c = "DexClassLoader"
        $d = "loadClass"
    condition:
        $a and $b and ($c or $d)
}c