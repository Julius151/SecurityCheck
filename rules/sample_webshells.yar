rule php_suspicious_eval_base64 {
  meta:
    author = "starter"
    description = "Obfuscated PHP/webshell patterns (tightened)"
    score = 5
  strings:
    $php_open = "<?php" ascii nocase
    $b64 = "base64_decode(" nocase
    $eval = "eval(" nocase
    $inflate = "gzinflate(" nocase
    $preg_e = /preg_replace\s*\(.+\/e/ nocase
  condition:
    // scope to typical PHP/HTML, keep small files
    (filename matches /\\.(php|phtml|php[3457]?|inc|tpl|html?)$/i) and
    filesize < 300KB and
    // require PHP context and at least one suspicious token
    $php_open and 1 of ($b64, $eval, $inflate, $preg_e)
}

rule suspicious_iframe_hidden {
  meta:
    description = "Hidden iframe typical in injected spam (tightened)"
    score = 3
  strings:
    $ifr = "<iframe" nocase
    $hide = "display:none" nocase
  condition:
    (filename matches /\\.(php|phtml|html?)$/i) and
    filesize < 300KB and
    // require proximity (likely same tag/style block)
    $ifr and $hide and
    for any i in (1..#ifr): ( @ifr[i] <= @hide and (@hide - @ifr[i]) < 200 )
}