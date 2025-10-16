rule detect_mirai
{
    strings:
        $s = "REPLACE_WITH_REAL_SIGNATURE"
    condition:
        $s
}

rule detect_wannacry
{
    strings:
        $s1 = "REPLACE_WITH_REAL_SIGNATURE"
        $s2 = "REPLACE_WITH_REAL_SIGNATURE"
        $s3 = "REPLACE_WITH_REAL_SIGNATURE"
    condition:
        2 of them
}

rule detect_emotet
{
    strings:
        $s1 = "REPLACE_WITH_REAL_SIGNATURE"
        $s2 = "REPLACE_WITH_REAL_SIGNATURE"
        $s3 = "REPLACE_WITH_REAL_SIGNATURE"
    condition:
        2 of them
}

rule detect_petya
{
    strings:
        $s1 = "REPLACE_WITH_REAL_SIGNATURE"
        $s2 = "REPLACE_WITH_REAL_SIGNATURE"
        $s3 = "REPLACE_WITH_REAL_SIGNATURE"
    condition:
        2 of them
}

rule detect_zeus
{
    strings:
        $s1 = "REPLACE_WITH_REAL_SIGNATURE"
        $s2 = "REPLACE_WITH_REAL_SIGNATURE"
        $s3 = "REPLACE_WITH_REAL_SIGNATURE"
        $s4 = "REPLACE_WITH_REAL_SIGNATURE"
    condition:
        3 of them
}

rule detect_stuxnet
{
    strings:
        $s1 = "REPLACE_WITH_REAL_SIGNATURE"
        $s2 = "REPLACE_WITH_REAL_SIGNATURE"
        $s3 = "REPLACE_WITH_REAL_SIGNATURE"
        $s4 = "REPLACE_WITH_REAL_SIGNATURE"
        $s5 = "REPLACE_WITH_REAL_SIGNATURE"
    condition:
        4 of them
}