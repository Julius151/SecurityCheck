rule php_suspicious_eval_base64 {
  meta:
    author = "starter"
    description = "Detect common obfuscated PHP webshell patterns"
    score = 5
  strings:
    $s1 = "base64_decode(" nocase
    $s2 = "eval(" nocase
    $s3 = "gzinflate(" nocase
    $s4 = "/e" ascii
  condition:
    (any of ($s1, $s2, $s3, $s4)) and filesize < 200000
}

rule suspicious_iframe_hidden {
  meta:
    description = "Hidden iframe typical in injected spam"
    score = 3
  strings:
    $i1 = "<iframe" nocase
    $i2 = "display:none" nocase
  condition:
    all of them
}