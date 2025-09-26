#!/usr/bin/env bash
set -euo pipefail

ensure_yara_ready() {
  set -e
  : "${YARA_RULES_PATH:=$( [ -f /etc/yara_rules_path ] && cat /etc/yara_rules_path || echo /rules/compiled/php_webshells.yarac )}"

  # If user mounted raw rules at /rules, normalize & compile on the fly
  if [ -d /rules ] && [ -z "${SKIP_YARA_COMPILE:-}" ]; then
    mapfile -t RULES < <(find /rules -type f \( -name '*.yar' -o -name '*.yara' \) | sort)
    if [ "${#RULES[@]}" -gt 0 ]; then
      echo "[yara] Normalizing & compiling mounted rules..."
      for f in "${RULES[@]}"; do
        dos2unix "$f" || true
        sed -i '1s/^\xEF\xBB\xBF//' "$f"
      done
      mkdir -p /rules/compiled
      yarac "${RULES[@]}" /rules/compiled/php_webshells.yarac
      YARA_RULES_PATH="/rules/compiled/php_webshells.yarac"
    fi
  fi

  if [ ! -s "$YARA_RULES_PATH" ]; then
    echo "[yara] ERROR: compiled rules not found at $YARA_RULES_PATH" >&2
    exit 1
  fi
  export YARA_RULES_PATH
  echo "[yara] Using rules: $YARA_RULES_PATH"
}

ensure_yara_ready
exec /usr/local/bin/scan.sh
