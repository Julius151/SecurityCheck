FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Base packages & scanners
RUN apt-get update && apt-get install -y --no-install-recommends \
  curl wget ca-certificates gnupg lsb-release git build-essential \
  php-cli php-xml php-mbstring unzip sudo python3 python3-pip jq \
  clamav clamav-daemon clamav-freshclam \
  yara libyara-dev \
  libssl-dev \
  dos2unix libc-bin \
  && apt-get clean && rm -rf /var/lib/apt/lists/*

# Python bindings for YARA (correct package)
RUN pip3 install --no-cache-dir yara-python

# Install Maldet (Linux Malware Detect)
RUN cd /tmp && \
  wget -q https://www.rfxn.com/downloads/maldetect-current.tar.gz && \
  tar -xzf maldetect-current.tar.gz && \
  cd maldetect-* && \
  ./install.sh && \
  rm -rf /tmp/maldetect-*

# Install WP-CLI (optional)
RUN curl -sSL https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -o /usr/local/bin/wp && \
  chmod +x /usr/local/bin/wp || true

# Update ClamAV DB (ignore failures)
RUN sed -i 's/^Example/#Example/' /etc/clamav/freshclam.conf || true && \
  freshclam || true

# Workspace, rules & scripts
RUN mkdir -p /workspace /rules /reports /data
# If you have rules locally, copy them; if not, we'll create a fallback below
# (keep the COPY even if your local rules/ is empty; Docker handles it)
COPY rules/ /rules/
COPY scan.sh /usr/local/bin/scan.sh
COPY entrypoint.sh /usr/local/bin/entrypoint.sh

# Build-time: normalize & compile rules (fail fast on bad rules)
RUN set -eux; \
  find /rules -type f \( -name '*.yar' -o -name '*.yara' \) > /tmp/rulelist || true; \
  if [ -s /tmp/rulelist ]; then \
    while IFS= read -r f; do \
      dos2unix "$f" || true; \
      sed -i '1s/^\xEF\xBB\xBF//' "$f"; \
    done < /tmp/rulelist; \
    mkdir -p /rules/compiled; \
    yarac $(tr '\n' ' ' </tmp/rulelist) /rules/compiled/php_webshells.yarac; \
  else \
    echo "No .yar files found; creating fallback"; \
    mkdir -p /rules; \
    printf '%s\n' \
'/* fallback YARA rules */' \
'' \
'rule php_suspicious_eval_base64 {' \
'  meta:' \
'    author = "starter"' \
'    description = "Detect common obfuscated PHP webshell patterns"' \
'    score = 5' \
'  strings:' \
'    $s1 = "base64_decode(" nocase' \
'    $s2 = "eval(" nocase' \
'    $s3 = "gzinflate(" nocase' \
'    $s4 = /\/e\b/' \
'  condition:' \
'    any of ($s1, $s2, $s3, $s4) and filesize < 200000' \
'}' \
'' \
'rule suspicious_iframe_hidden {' \
'  meta:' \
'    description = "Hidden iframe typical in injected spam"' \
'    score = 3' \
'  strings:' \
'    $i1 = "<iframe" nocase' \
'    $i2 = "display:none" nocase' \
'  condition:' \
'    all of them' \
'}' \
    > /rules/php_webshells.yar; \
    dos2unix /rules/php_webshells.yar || true; \
    sed -i '1s/^\xEF\xBB\xBF//' /rules/php_webshells.yar; \
    mkdir -p /rules/compiled; \
    yarac /rules/php_webshells.yar /rules/compiled/php_webshells.yarac; \
  fi; \
  echo "/rules/compiled/php_webshells.yarac" > /etc/yara_rules_path

# Default runtime rules path (can be overridden)
ENV YARA_RULES_PATH=/rules/compiled/php_webshells.yarac

RUN chmod 755 /usr/local/bin/scan.sh /usr/local/bin/entrypoint.sh
WORKDIR /workspace
ENTRYPOINT ["/usr/bin/env", "bash", "/usr/local/bin/entrypoint.sh"]
