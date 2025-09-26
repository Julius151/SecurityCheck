#!/usr/bin/env bash
set -euo pipefail

SITE_NAME=${SITE_NAME:-unknown}
SITE_DIR=${SITE_DIR:-/data/site}
REPORT_DIR=${REPORT_DIR:-/reports}
TMP_DIR=/tmp/site-scan
TIMESTAMP=$(date +"%Y%m%dT%H%M%S")
REPORT_JSON="${REPORT_DIR}/${SITE_NAME}-scan.json"
REPORT_HTML="${REPORT_DIR}/${SITE_NAME}-scan.html"
QUIET=${QUIET:-0}

mkdir -p "$REPORT_DIR" "$TMP_DIR"
log() { if [ "$QUIET" -eq 0 ]; then echo "[$(date -u +'%Y-%m-%dT%H:%M:%SZ')] $*"; fi }

jq_init() {
  cat >"$REPORT_JSON" <<JSON
{
  "site_name": "$SITE_NAME",
  "timestamp": "$TIMESTAMP",
  "site_dir": "$SITE_DIR",
  "results": {
    "wpcli_checksums": null,
    "maldet": null,
    "clamav": null,
    "yara": null,
    "grep_heuristics": null
  }
}
JSON
}

jq_put_json() {
  local key=$1; local json_file=$2
  local tmp; tmp=$(mktemp)
  jq --arg k "$key" --slurpfile v "$json_file" '.results[$k] = $v[0]' "$REPORT_JSON" > "$tmp" && mv "$tmp" "$REPORT_JSON"
}

jq_put_text() {
  local key=$1; local text_file=$2
  local tmp; tmp=$(mktemp)
  [ -s "$text_file" ] || touch "$text_file"
  sed -r 's/\x1b\[[0-9;]*m//g' "$text_file" > "${text_file}.nocolor" 2>/dev/null || cp "$text_file" "${text_file}.nocolor"
  jq --arg k "$key" --rawfile rf "${text_file}.nocolor" '.results[$k] = { "raw": $rf }' "$REPORT_JSON" > "$tmp" && mv "$tmp" "$REPORT_JSON"
}

if [ ! -d "$SITE_DIR" ]; then
  echo "ERROR: SITE_DIR ($SITE_DIR) not found or not a directory" >&2
  exit 2
fi

jq_init

# =========================
# 1) WP-CLI checksums (optional)
# =========================
log "STEP 1: WP-CLI checksum verification (optional)"
WPCLI_OUT="$TMP_DIR/wpcli.json"
if command -v wp >/dev/null 2>&1 && [ -f "${SITE_DIR}/wp-includes/version.php" ]; then
  pushd "$SITE_DIR" >/dev/null
  CORE_OUT=$(wp core verify-checksums --format=json 2>/dev/null || echo '[]')
  PLUG_LIST_JSON=$(wp plugin list --field=name --format=json 2>/dev/null || echo '[]')
  PLUGINS_SUMMARY="{}"
  if echo "$PLUG_LIST_JSON" | jq -e 'type=="array" and length>0' >/dev/null 2>&1; then
    PLUGINS_SUMMARY=$(
      echo "$PLUG_LIST_JSON" | jq -r '.[]' | while read -r p; do
        RES=$(wp plugin verify-checksums "$p" --format=json 2>/dev/null || echo '"not_available"')
        echo "\"$p\": $RES"
      done | jq -s 'add' 2>/dev/null || echo "{}"
    )
  fi
  popd >/dev/null
  cat >"$WPCLI_OUT" <<JSON
{"core": $CORE_OUT, "plugins": $PLUGINS_SUMMARY}
JSON
else
  echo '{"note":"wp-cli not available or not a WP directory; step skipped"}' > "$WPCLI_OUT"
fi
jq_put_json "wpcli_checksums" "$WPCLI_OUT"

# =========================
# 2) Maldet
# =========================
log "STEP 2: Maldet (LMD) quick scan"
malout="$TMP_DIR/maldet.out"
if command -v maldet >/dev/null 2>&1; then
  maldet -u >/dev/null 2>&1 || true
  maldet -a "$SITE_DIR" > "$malout" 2>&1 || true
else
  echo "maldet not installed; step skipped" > "$malout"
fi
jq_put_text "maldet" "$malout"

# =========================
# 3) ClamAV
# =========================
log "STEP 3: ClamAV scan (clamscan)"
clamout="$TMP_DIR/clamav.out"
if command -v clamscan >/dev/null 2>&1; then
  freshclam --quiet || true
  clamscan -ri --exclude-dir="^/sys" "$SITE_DIR" > "$clamout" 2>&1 || true
else
  echo "clamscan not installed; step skipped" > "$clamout"
fi
jq_put_text "clamav" "$clamout"

# =========================
# 4) YARA ruleset scanning
# =========================
log "STEP 4: YARA ruleset scanning"
yaraout="$TMP_DIR/yara.out"

if command -v yara >/dev/null 2>&1; then
  RULES_PATH="${YARA_RULES_PATH:-/rules/compiled/php_webshells.yarac}"
  if [ -s "$RULES_PATH" ]; then
    if [[ "$RULES_PATH" == *.yarac ]]; then
      yara -C -r "$RULES_PATH" "$SITE_DIR" > "$yaraout" 2>&1 || true
    else
      yara -r "$RULES_PATH" "$SITE_DIR" > "$yaraout" 2>&1 || true
    fi
  else
    # Fallback: run against any raw .yar files
    mapfile -t YRFILES < <(find /rules -type f \( -iname '*.yar' -o -iname '*.yara' \) 2>/dev/null || true)
    if ((${#YRFILES[@]})); then
      yara -r "${YRFILES[@]}" "$SITE_DIR" > "$yaraout" 2>&1 || true
    else
      echo "No YARA rules found (skipped)" > "$yaraout"
    fi
  fi
else
  echo "yara not installed; step skipped" > "$yaraout"
fi
jq_put_text "yara" "$yaraout"

# 5) Grep heuristics
log "STEP 5: Grep heuristics for suspicious tokens"
grepout="$TMP_DIR/grep.out"
grep -RIn --exclude-dir=wp-content/uploads -E "eval\(|base64_decode\(|gzinflate\(|preg_replace\(.+\/e|str_rot13\(|shell_exec\(|passthru\(|system\(" "$SITE_DIR" > "$grepout" 2>/dev/null || true
jq_put_text "grep_heuristics" "$grepout"

# HTML (unchanged styling)
render_section() {
  local key="$1" title="$2" tmp_summary tmp_body type
  tmp_summary=$(mktemp); tmp_body=$(mktemp)
  type=$(jq -r --arg k "$key" '.results[$k] | if has("raw") then "text" else (type) end' "$REPORT_JSON")
  case "$key" in
    clamav) grep -E "Infected files:" -m1 "$clamout" 2>/dev/null | sed 's/^/ /' > "$tmp_summary" || echo "" > "$tmp_summary" ;;
    maldet) grep -E "signatures loaded:|scan returned|hits|quarantined" -m3 "$malout" 2>/dev/null | sed 's/^/ /' > "$tmp_summary" || echo "" > "$tmp_summary" ;;
    *) echo "" > "$tmp_summary" ;;
  esac
  if [ "$type" = "text" ]; then
    jq -r --arg k "$key" '.results[$k].raw' "$REPORT_JSON" > "$tmp_body"
  else
    jq -r --arg k "$key" '.results[$k]' "$REPORT_JSON" | jq . > "$tmp_body"
  fi
  cat <<HTML
<details>
  <summary>$title<span class="pill">$type</span> <span class="muted">$(tr -d '\n' < "$tmp_summary")</span></summary>
  <div class="body"><pre>$(cat "$tmp_body")</pre></div>
</details>
HTML
}

SECTIONS_HTML=$(cat <<HTML
$(render_section "wpcli_checksums" "WordPress integrity (WP-CLI) ")
$(render_section "maldet"          "Linux Malware Detect (maldet) ")
$(render_section "clamav"          "ClamAV ")
$(render_section "yara"            "YARA rules ")
$(render_section "grep_heuristics" "Heuristic grep patterns ")
HTML
)

TEMPLATE_PATH="${TEMPLATE_PATH:-/workspace/report.template.html}"
write_fallback_html() {
  cat > "$REPORT_HTML" <<HTML
<!doctype html><html><head><meta charset="utf-8"><title>Scan Report - $SITE_NAME</title>
<style>
  body{font-family:system-ui, Arial; max-width:980px; margin:24px;}
  pre{background:#0b0f14; color:#e7edf4; padding:12px; border-radius:8px; overflow:auto; white-space:pre-wrap;}
  details{border:1px solid #e2e8f0; border-radius:12px; background:#ffffff; margin-bottom:12px}
  details summary{cursor:pointer; padding:12px 14px; font-weight:600; list-style:none}
  .muted{color:#64748b}
  .pill{display:inline-block; padding:2px 8px; border-radius:999px; font-size:12px; background:#e2e8f0; color:#0b0f14; margin-left:8px}
</style></head><body>
<h1>Scan report for <em>$SITE_NAME</em></h1>
<p><strong>Last scan:</strong> $TIMESTAMP &nbsp;·&nbsp; <strong>Scanned directory:</strong> <code>$SITE_DIR</code></p>
$SECTIONS_HTML
</body></html>
HTML
}
if [ -f "$TEMPLATE_PATH" ]; then
  tmpl="$(cat "$TEMPLATE_PATH")"
  tmpl="${tmpl//\{\{SITE_NAME\}\}/$SITE_NAME}"
  tmpl="${tmpl//\{\{TIMESTAMP\}\}/$TIMESTAMP}"
  tmpl="${tmpl//\{\{SITE_DIR\}\}/$SITE_DIR}"
  tmpl="${tmpl//\{\{RESULT_SECTIONS\}\}/$SECTIONS_HTML}"
  printf "%s" "$tmpl" > "$REPORT_HTML"
else
  write_fallback_html
fi

log "Scan complete. JSON: $REPORT_JSON  HTML: $REPORT_HTML"
jq '.' "$REPORT_JSON"
