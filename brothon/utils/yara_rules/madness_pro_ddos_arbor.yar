rule madness {
  meta:
   author = "Jason Jones"
   author_email = "jasonjones@arbor.net"
   date = "2014-01-15"
   description = "Identify Madness Pro DDoS Malware"
  strings:
    $ua1 = "TW96aWxsYS81LjAgKFdpbmRvd3M7IFU7IFdpbmRvd3MgTlQgNS4xOyBlbi1VUzsgcnY6MS44LjAuNSkgR2Vja28vMjAwNjA3MzEgRmlyZWZveC8xLjUuMC41IEZsb2NrLzAuNy40LjE"
    $ua2 = "TW96aWxsYS81LjAgKFgxMTsgVTsgTGludXggMi40LjItMiBpNTg2OyBlbi1VUzsgbTE4KSBHZWNrby8yMDAxMDEzMSBOZXRzY2FwZTYvNi4wMQ=="
    $str1= "document.cookie=" fullword
    $str2 = "[\"cookie\",\"" fullword
    $str3 = "\"realauth=" fullword
    $str4 = "\"location\"];" fullword
    $str5 = "d3Rm" fullword
    $str6 = "ZXhl" fullword
  condition:
    all of them
}
