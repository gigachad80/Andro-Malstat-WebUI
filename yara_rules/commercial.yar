rule Commercial_Packers {
    meta:
        description = "Detects if the APK is packed/protected (Hides malware)"
        severity = "Medium"
    strings:
        $qihoo = "libjiagu.so"
        $tencent = "libshell.so"
        $secneo = "libbangcle.so"
        $baidu = "libbaiduprotect.so"
        $ali = "libmobisec.so"
    condition:
        any of them
}
