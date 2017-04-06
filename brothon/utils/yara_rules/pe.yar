private rule is_pe
{
    meta:                                        
        description = "Windows executable file"
    condition:
        // MZ signature at offset 0 and ...
        uint16(0) == 0x5A4D and 
        // ... PE signature at offset stored in MZ header at 0x3C
        uint32(uint32(0x3C)) == 0x00004550
}
