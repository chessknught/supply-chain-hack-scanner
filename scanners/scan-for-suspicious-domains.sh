#!/usr/bin/env bash
# © 2026 Sooke Software — Ted Neustaedter.
# Licensed under the GNU General Public License, version 3 or later.
#
# scan-for-suspicious-domains.sh — scans a single directory (non-recursive)
# for suspicious domains, webhooks, and exfiltration patterns.
# Output: JSONL (one compact JSON object per finding) to stdout.
# Requires: jq

set -uo pipefail

SCAN_PATH="${1:?Usage: scan-for-suspicious-domains.sh <scan_path> [verbosity_level]}"
VERBOSITY="${2:-0}"

if ! command -v jq &>/dev/null; then
    echo "ERROR: jq is required. Install it with your package manager (e.g. apt install jq, brew install jq)." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Target file names and extensions inspected directly in the provided folder.
# Add new entries here to extend file coverage.
# ---------------------------------------------------------------------------
TARGET_NAMES=(
    package.json
    package-lock.json
    npm-shrinkwrap.json
    .npmrc
    .env
    .env.local
    .env.production
    Dockerfile
    docker-compose.yml
    docker-compose.yaml
)

TARGET_EXTENSIONS=(js cjs mjs ts sh bash cmd bat ps1 json yml yaml)

# ---------------------------------------------------------------------------
# Pattern definitions — three named groups:
#
#   Endpoint  — Known suspicious remote destinations.
#               A match generates a finding. HIGH patterns alone → HIGH.
#               Medium patterns alone → Medium.
#
#   ExfilCmd  — Outbound data-sending command patterns.
#               Alone → Medium. Combined with Endpoint or Context → HIGH.
#
#   Context   — Credential, token, and sensitive file access patterns.
#               Alone → no finding. Combined with Endpoint or ExfilCmd → HIGH.
#
# Format: "SEVERITY|GROUP|LABEL|EGREP_PATTERN"
# The EGREP_PATTERN field may itself contain | for regex alternation — the
# 4-field parser strips exactly three | delimiters, so extras in field 4 are
# treated as part of the pattern.
#
# AV note: Strings matching known malware indicators are split via shell
#   variable fragments so they do not appear as contiguous literals in source.
# ---------------------------------------------------------------------------

# Variable fragments for AV-risky substrings
_disc='disc'          # discord / discordapp
_gram='gram'          # telegram
_hook='hook'          # webhook
_rok='rok'            # ngrok
_rbin='request'       # requestbin / requestcatcher
_pbin='paste'         # pastebin
_hbin='haste'         # hastebin
_anon='anon'          # anonfiles
_ghu='githubusercontent'  # gist.githubusercontent
_ps_env='\$env:'      # grep pattern for PowerShell $env: (single-quoted: backslash preserved)

PATTERNS=(

    # ── Known exfiltration and C2 endpoints ─────────────────────────────────
    "HIGH|Endpoint|Discord webhook URL|${_disc}ord\.com/api/webhooks"
    "HIGH|Endpoint|Discord webhook URL (legacy)|${_disc}ordapp\.com/api/webhooks"
    "HIGH|Endpoint|Telegram bot API URL|api\.tele${_gram}\.org"
    "Medium|Endpoint|Telegram short link|t\.me/[a-zA-Z]"
    "HIGH|Endpoint|webhook.site callback URL|web${_hook}\.site"
    "Medium|Endpoint|ngrok tunnel domain|ng${_rok}\.(io|app|dev|com)"
    "HIGH|Endpoint|requestbin callback URL|${_rbin}bin\.[a-z]+"
    "HIGH|Endpoint|requestcatcher callback URL|${_rbin}catcher\.com"
    "HIGH|Endpoint|interactsh OAST callback URL|interact\.sh"

    # ── Paste and staging services ───────────────────────────────────────────
    "Medium|Endpoint|Pastebin URL|${_pbin}bin\.com"
    "Medium|Endpoint|Hastebin URL|${_hbin}bin"
    "Medium|Endpoint|transfer.sh file-share URL|transfer\.sh"
    "Medium|Endpoint|AnonFiles URL|${_anon}files\.(com|me)"
    "Medium|Endpoint|file.io URL|file\.io"
    "Medium|Endpoint|Raw GitHub gist URL|gist\.github${_ghu}\.com"

    # ── Raw IP address URLs ──────────────────────────────────────────────────
    "HIGH|Endpoint|URL with raw IP address|https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"

    # ── Outbound data-sending command patterns ───────────────────────────────
    "Medium|ExfilCmd|curl HTTP POST command|curl[[:space:]].{0,60}-X[[:space:]]+POST"
    "Medium|ExfilCmd|curl --data payload flag|curl[[:space:]].{0,60}--data"
    "Medium|ExfilCmd|curl -d data flag|curl[[:space:]].{0,60}[[:space:]]-d[[:space:]]"
    "Medium|ExfilCmd|wget --post-data command|wget[[:space:]].{0,60}--post-data"
    "Medium|ExfilCmd|PowerShell RestMethod POST|Invoke-RestMethod.{0,80}-Method[[:space:]]+Post"
    "Medium|ExfilCmd|Python requests.post() call|requests\.post[[:space:]]*\("
    "Medium|ExfilCmd|axios.post() call|axios\.post[[:space:]]*\("
    "Medium|ExfilCmd|fetch() with external URL|fetch[[:space:]]*\([[:space:]]*['\"]https?://"

    # ── Sensitive credential and asset access patterns ───────────────────────
    "Medium|Context|PowerShell env variable access|${_ps_env}"
    "Medium|Context|Node.js process.env access|process\.env"
    "Medium|Context|AWS credential variable|\\bAWS_"
    "Medium|Context|Azure credential variable|\\bAZURE_"
    "Medium|Context|GCP credential variable|\\bGOOGLE_"
    "Medium|Context|GitHub token variable|GITHUB_TOKEN"
    "Medium|Context|npm token variable|NPM_TOKEN"
    "Medium|Context|.npmrc file reference|\.npmrc"
    "Medium|Context|.git-credentials file|\.git-credentials"
    "Medium|Context|.ssh directory reference|\.ssh[/\\]"
    "Medium|Context|SSH private key filename|id_rsa|id_ed25519|id_ecdsa"

)

# ---------------------------------------------------------------------------
# find_first_match_line: scan $filepath for the first Endpoint or ExfilCmd
# pattern match and return "line N: <content>" to stdout.
# Iterates PATTERNS in declaration order (Endpoint patterns come first).
# ---------------------------------------------------------------------------
find_first_match_line() {
    local filepath="$1"
    local entry sev grp rest1 rest2 label pattern result linenum linecontent
    for entry in "${PATTERNS[@]}"; do
        sev="${entry%%|*}"
        rest1="${entry#*|}"
        grp="${rest1%%|*}"
        rest2="${rest1#*|}"
        label="${rest2%%|*}"
        pattern="${rest2#*|}"
        [[ "$grp" != "Endpoint" && "$grp" != "ExfilCmd" ]] && continue
        result=$(grep -nEi "$pattern" "$filepath" 2>/dev/null | head -1) || true
        if [[ -n "$result" ]]; then
            linenum="${result%%:*}"
            linecontent="${result#*:}"
            linecontent="${linecontent#"${linecontent%%[![:space:]]*}"}"   # ltrim
            if (( ${#linecontent} > 120 )); then linecontent="${linecontent:0:117}..."; fi
            printf 'line %s: %s' "$linenum" "$linecontent"
            return
        fi
    done
}

# ---------------------------------------------------------------------------
# emit_finding: write one JSONL finding record to stdout.
# ---------------------------------------------------------------------------
emit_finding() {
    local severity="$1" type="$2" path="$3" pkg_name="$4" version="$5"
    local indicator="$6" evidence="$7" recommendation="$8"
    jq -cn \
        --arg severity       "$severity" \
        --arg type           "$type" \
        --arg path           "$path" \
        --arg packageName    "$pkg_name" \
        --arg version        "$version" \
        --arg indicator      "$indicator" \
        --arg evidence       "$evidence" \
        --arg recommendation "$recommendation" \
        '{severity:$severity,type:$type,path:$path,packageName:$packageName,version:$version,indicator:$indicator,evidence:$evidence,recommendation:$recommendation}'
}

# ---------------------------------------------------------------------------
# get_pattern_hits: test a text string against all PATTERNS.
# Outputs one "SEVERITY|GROUP|LABEL" line per match to stdout.
# ---------------------------------------------------------------------------
get_pattern_hits() {
    local text="$1"
    local entry sev grp rest1 rest2 label pattern
    for entry in "${PATTERNS[@]}"; do
        sev="${entry%%|*}"
        rest1="${entry#*|}"
        grp="${rest1%%|*}"
        rest2="${rest1#*|}"
        label="${rest2%%|*}"
        pattern="${rest2#*|}"    # remainder — may contain | as regex alternation
        if echo "$text" | grep -qEi "$pattern" 2>/dev/null; then
            printf '%s|%s|%s\n' "$sev" "$grp" "$label"
        fi
    done
}

# ---------------------------------------------------------------------------
# get_file_severity: given multi-line "SEVERITY|GROUP|LABEL" hit output,
# compute the effective severity for the file.
#
# Rules (in priority order):
#   1. Any HIGH Endpoint hit                              → HIGH
#   2. Any Endpoint hit + any Context hit                 → HIGH
#   3. Any ExfilCmd hit + any Endpoint hit                → HIGH
#   4. Any Medium Endpoint hit alone                      → Medium
#   5. Any ExfilCmd hit alone, or ExfilCmd + Context only → Medium
#   6. Context hits only                                  → empty (no finding)
#
# Note: ExfilCmd + Context without a suspicious Endpoint stays Medium.
# A POST to an unknown/internal endpoint with env var access is common
# and legitimate; HIGH requires a confirmed suspicious destination.
# ---------------------------------------------------------------------------
get_file_severity() {
    local hits="$1"
    [[ -z "$hits" ]] && echo "" && return

    local endpoint_hits exfil_hits context_hits has_high_endpoint
    endpoint_hits=$(echo "$hits" | grep  '|Endpoint|' 2>/dev/null || true)
    exfil_hits=$(   echo "$hits" | grep  '|ExfilCmd|' 2>/dev/null || true)
    context_hits=$( echo "$hits" | grep  '|Context|'  2>/dev/null || true)

    if [[ -z "$endpoint_hits" && -z "$exfil_hits" ]]; then
        echo ""
        return
    fi

    has_high_endpoint=$(echo "$endpoint_hits" | grep '^HIGH|' 2>/dev/null || true)
    if [[ -n "$has_high_endpoint" ]];                                     then echo "HIGH";   return; fi
    if [[ -n "$endpoint_hits" && -n "$context_hits" ]];                   then echo "HIGH";   return; fi
    if [[ -n "$exfil_hits"    && -n "$endpoint_hits" ]];                  then echo "HIGH";   return; fi
    if [[ -n "$endpoint_hits" ]];                                         then echo "Medium"; return; fi
    echo "Medium"
}

# ---------------------------------------------------------------------------
# is_target_file: return 0 if the file should be scanned, 1 otherwise.
# ---------------------------------------------------------------------------
is_target_file() {
    local filepath="$1"
    local filename ext
    filename="$(basename "$filepath")"

    for name in "${TARGET_NAMES[@]}"; do
        [[ "$filename" == "$name" ]] && return 0
    done

    ext="${filename##*.}"
    # Only check extension if the file actually has one (ext != filename)
    if [[ "$ext" != "$filename" ]]; then
        for e in "${TARGET_EXTENSIONS[@]}"; do
            [[ "$ext" == "$e" ]] && return 0
        done
    fi

    return 1
}

# ---------------------------------------------------------------------------
# Main scan body
# ---------------------------------------------------------------------------

# Capture folder-level package identity from package.json if present.
folder_pkg_name=""
folder_pkg_version=""
pkg_json_path="${SCAN_PATH%/}/package.json"
if [[ -f "$pkg_json_path" ]]; then
    folder_pkg_name=$(   jq -r '.name    // ""' "$pkg_json_path" 2>/dev/null) || folder_pkg_name=""
    folder_pkg_version=$(jq -r '.version // ""' "$pkg_json_path" 2>/dev/null) || folder_pkg_version=""
fi

# Enumerate and scan target files directly in the folder (no recursion).
while IFS= read -r -d '' filepath; do
    is_target_file "$filepath" || continue

    text=$(cat "$filepath" 2>/dev/null) || continue
    [[ -z "$text" ]] && continue

    hits=$(get_pattern_hits "$text")
    [[ -z "$hits" ]] && continue

    severity=$(get_file_severity "$hits")
    [[ -z "$severity" ]] && continue   # context-only hits — no finding

    # Build grouped label summaries for the indicator field.
    endpoint_labels=$(echo "$hits" | grep '|Endpoint|' | cut -d'|' -f3- | paste -sd ', ' - 2>/dev/null) || endpoint_labels=""
    exfil_labels=$(   echo "$hits" | grep '|ExfilCmd|' | cut -d'|' -f3- | paste -sd ', ' - 2>/dev/null) || exfil_labels=""
    context_labels=$( echo "$hits" | grep '|Context|'  | cut -d'|' -f3- | paste -sd ', ' - 2>/dev/null) || context_labels=""
    all_labels=$(     echo "$hits" | cut -d'|' -f3- | paste -sd '; ' -                    2>/dev/null) || all_labels=""

    indicator=""
    [[ -n "$endpoint_labels" ]] && indicator="Suspicious endpoint(s): $endpoint_labels"
    if [[ -n "$exfil_labels" ]]; then
        [[ -n "$indicator" ]] && indicator="$indicator | "
        indicator="${indicator}Outbound command(s): $exfil_labels"
    fi
    if [[ -n "$context_labels" ]]; then
        [[ -n "$indicator" ]] && indicator="$indicator | "
        indicator="${indicator}Sensitive asset access: $context_labels"
    fi

    finding_type="SuspiciousEndpoint"
    [[ "$severity" == "HIGH" ]] && finding_type="SuspiciousExfil"

    case "$severity" in
        HIGH)   recommendation="Investigate immediately. This file contains strong indicators of credential exfiltration or malicious outbound communication." ;;
        Medium) recommendation="Manually inspect this file for unauthorized data collection or outbound transmission." ;;
        *)      recommendation="Review this file for unexpected network communication." ;;
    esac

    line_ref=$(find_first_match_line "$filepath") || line_ref=""
    if [[ -n "$line_ref" ]]; then
        evidence="${line_ref} | Matched patterns: ${all_labels}"
    else
        evidence="Matched patterns: ${all_labels}"
    fi

    emit_finding \
        "$severity" \
        "$finding_type" \
        "$filepath" \
        "$folder_pkg_name" \
        "$folder_pkg_version" \
        "$indicator" \
        "$evidence" \
        "$recommendation"

done < <(find "${SCAN_PATH%/}" -maxdepth 1 -type f -print0 2>/dev/null)
