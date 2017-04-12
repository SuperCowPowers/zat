rule meterpreter_detected
{
    meta:                                        
        description = "Metasploit Meterpreter"
    strings:
        $a = "priv_elevate_getsystem" nocase
        $b = "priv_passwd_get_sam_hashes" nocase
    condition:
        $a and $b
}
