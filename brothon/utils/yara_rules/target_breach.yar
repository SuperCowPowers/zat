rule CrowdStrike_targetbreach_exfil
{
    meta:
        description = "Tool Responsible for Exfiltration of CC Data."
        last_modified = "2014-01-16"
        version = "1.0"
        in_the_wild = true
        copyright = "CrowdStrike, Inc"
    strings:
        $fmt = "data_%d_%d_%d_%d_%d.txt"
        $scramble1 = "\"-BFr423mI_6uaMtg$bxl\\sd1iU/0ok.cpe"
        $scramble2 = "gBb63-t2p_.rkd0uaeU/x1c$s\\o4il"
        $scramble3 = "x\"a-201Mt6b3sI$ /ceBok_i\\m.rdpU4Fulg"
        $scramble4 = "omv3.a 1%tNd\\4ils60n2Te_w"
        $scramble5 = "4mei gd2%rob-"
        $scramble6 = "8pCt1wq_hynlsc0.u9a"
    condition:
        $fmt and 1 of ($scramble*)
}
 
rule CrowdStrike_blackpos_memscanner
{
    meta:
        description = "Tool Responsible for Scanning Memory For CC Data."
        last_modified = "2014-01-16"
        version = "1.0"
        in_the_wild = true
        copyright = "CrowdStrike, Inc"
    strings:
        $message1 = "S region:"
        $message2 = " found ["
        $message3 = "] bytes of pattern:["
        $message4 = "CC2 region:"
        $message5 = "CC memregion:"
        $message6 = "KAPTOXA"
        $message7 = "=== pid:"
        $message8 = "scan process with pid for kartoxa and string pattern:"
        $message9 = "scan process with pid for kartoxa:" 
        $message11 = "scan all processes for string pattern:" 
    condition:
        2 of ($message*)
}
