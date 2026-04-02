#!/usr/bin/env bash
# © 2026 Sooke Software — Ted Neustaedter. All rights reserved.
#
# scan-for-lifecycle-script-abuse.sh — scans a single directory (non-recursive)
# for suspicious lifecycle script abuse in package.json.
# Output: JSONL (one compact JSON object per finding) to stdout.

set -uo pipefail

SCAN_PATH="${1:?Usage: scan-for-lifecycle-script-abuse.sh <scan_path>}"

if ! command -v jq &>/dev/null; then
    echo "ERROR: jq is required. Install it with your package manager (e.g. apt install jq, brew install jq)." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Lifecycle script hooks to inspect in package.json.
# Add new hook names here as the npm lifecycle model evolves.
# ---------------------------------------------------------------------------
LIFECYCLE_KEYS=(
    preinstall
    install
    postinstall
    prepare
    prepublishOnly
)

# ---------------------------------------------------------------------------
# Suspicious pattern definitions.
# Format: "SEVERITY|LABEL|EGREP_PATTERN"
# Severity: HIGH | Medium | Info
#
# Severity escalation (applied in get_effective_severity):
#   - Any HIGH match              → HIGH
#   - Two or more Medium matches  → HIGH  (combined suspicious indicators)
#   - One Medium match            → Medium
#   - Nothing, or only Info       → Info
#
# Add new patterns here — nowhere else.
# ---------------------------------------------------------------------------
SUSPICIOUS_PATTERNS=(
    # Shell launchers
    "Medium|PowerShell invocation|powershell([[:space:]]|\.exe|$|-[a-zA-Z])"
    "Medium|pwsh invocation|pwsh([[:space:]]|\.exe|$|-[a-zA-Z])"
    "Medium|cmd /c shell execution|cmd[[:space:]]*/c"
    "Medium|bash -c shell execution|bash[[:space:]]+-c"
    "Medium|sh -c shell execution|sh[[:space:]]+-c"
    "Medium|node -e inline code execution|node[[:space:]]+-e"

    # Downloaders
    "Medium|curl download utility|\bcurl\b"
    "Medium|wget download utility|\bwget\b"
    "Medium|PowerShell web request (IWR)|Invoke-WebRequest|\biwr\b"
    "Medium|certutil (abused for downloads)|\bcertutil\b"
    "HIGH|bitsadmin downloader|\bbitsadmin\b"

    # System scripting / COM hosts
    "HIGH|mshta script host|\bmshta\b"
    "HIGH|rundll32 execution|\brundll32\b"
    "HIGH|regsvr32 execution|\bregsvr32\b"
    "HIGH|cscript script host|\bcscript\b"
    "HIGH|wscript script host|\bwscript\b"
    "Medium|PowerShell Start-Process|Start-Process"

    # Package runner abuse
    "Medium|npm exec|\bnpm[[:space:]]+exec\b"
    "Medium|npx execution|\bnpx\b"

    # Obfuscation and encoding
    "HIGH|eval() call|\beval[[:space:]]*\("
    "HIGH|Base64 decode (PowerShell)|FromBase64String"
    "Medium|base64 encoding/decoding|\bbase64\b"
    "HIGH|atob() Base64 decode|\batob[[:space:]]*\("
    "Medium|btoa() Base64 encode|\bbtoa[[:space:]]*\("

    # Process spawning
    "Medium|child_process module|child_process"
    "Medium|exec() call|\bexec[[:space:]]*\("
    "Medium|spawn() call|\bspawn[[:space:]]*\("

    # Hidden-window / stealth execution
    "HIGH|Hidden window flag|-WindowStyle[[:space:]]+[Hh]idden|-w[[:space:]]+[Hh]idden"
    "HIGH|Hidden window style property|WindowStyle[[:space:]]*=[[:space:]]*['\"]?[Hh]idden"

    # Exfiltration channels
    "HIGH|Discord webhook URL|discord\.com/api/webhooks"
    "HIGH|Telegram bot API URL|api\.telegram\.org/bot"

    # Raw IP in URL (download-from-IP)
    "HIGH|URL with raw IP address|https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}"

    # Any URL present (broad catch-all; lower severity)
    "Medium|URL present in lifecycle script|https?://"
)

# ---------------------------------------------------------------------------
# emit_finding: write one JSONL finding to stdout.
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
# get_pattern_hits: match a script value against all SUSPICIOUS_PATTERNS.
# Prints matching "SEVERITY|LABEL" entries, one per line.
# ---------------------------------------------------------------------------
get_pattern_hits() {
    local script_value="$1"
    local entry sev label pattern
    for entry in "${SUSPICIOUS_PATTERNS[@]}"; do
        sev="${entry%%|*}"
        rest="${entry#*|}"
        label="${rest%%|*}"
        pattern="${rest#*|}"
        if echo "$script_value" | grep -qEi "$pattern" 2>/dev/null; then
            printf '%s|%s\n' "$sev" "$label"
        fi
    done
}

# ---------------------------------------------------------------------------
# get_effective_severity: given multi-line "SEVERITY|LABEL" hit output,
# compute the escalated effective severity string.
# ---------------------------------------------------------------------------
get_effective_severity() {
    local hits="$1"
    local high_count medium_count
    high_count=$(  echo "$hits" | grep -c '^HIGH'   2>/dev/null || true)
    medium_count=$(echo "$hits" | grep -c '^Medium' 2>/dev/null || true)

    if   (( high_count   >= 1 )); then echo "HIGH"
    elif (( medium_count >= 2 )); then echo "HIGH"
    elif (( medium_count == 1 )); then echo "Medium"
    else                               echo "Info"
    fi
}

# ---------------------------------------------------------------------------
# scan_package_json: inspect lifecycle hooks in a single package.json file.
# ---------------------------------------------------------------------------
scan_package_json() {
    local filepath="$1"
    local pkg_name pkg_version
    pkg_name=$(   jq -r '.name    // ""' "$filepath" 2>/dev/null) || pkg_name=""
    pkg_version=$(jq -r '.version // ""' "$filepath" 2>/dev/null) || pkg_version=""

    local key script_value hits effective_severity matched_labels finding_type recommendation

    for key in "${LIFECYCLE_KEYS[@]}"; do
        script_value=$(jq -r --arg k "$key" '.scripts[$k] // ""' "$filepath" 2>/dev/null) || script_value=""
        [[ -z "$script_value" ]] && continue

        hits=$(get_pattern_hits "$script_value")

        if [[ -z "$hits" ]]; then
            # Hook exists but nothing suspicious — informational only.
            emit_finding \
                "Info" \
                "LifecycleScript" \
                "$filepath" \
                "$pkg_name" \
                "$pkg_version" \
                "Lifecycle script '$key' present — no suspicious patterns detected" \
                "scripts.${key}: $script_value" \
                "Verify that this lifecycle script is expected and has not been tampered with."
        else
            effective_severity=$(get_effective_severity "$hits")
            # Build a semicolon-separated list of matched labels (second field of each hit line)
            matched_labels=$(echo "$hits" | cut -d'|' -f2- | paste -sd '; ' -)

            if [[ "$effective_severity" != "Info" ]]; then
                finding_type="LifecycleScriptAbuse"
            else
                finding_type="LifecycleScript"
            fi

            case "$effective_severity" in
                HIGH)   recommendation="Investigate immediately. This lifecycle script contains strong indicators of malicious or highly suspicious behaviour." ;;
                Medium) recommendation="Manually inspect this lifecycle script. The patterns detected may indicate malicious activity." ;;
                *)      recommendation="Verify that this lifecycle script is expected and has not been tampered with." ;;
            esac

            emit_finding \
                "$effective_severity" \
                "$finding_type" \
                "$filepath" \
                "$pkg_name" \
                "$pkg_version" \
                "Lifecycle script '$key' — matched: $matched_labels" \
                "scripts.${key}: $script_value" \
                "$recommendation"
        fi
    done
}

# ---------------------------------------------------------------------------
# Main: inspect package.json in the given directory only (no recursion).
# ---------------------------------------------------------------------------
pkg_json="${SCAN_PATH%/}/package.json"
[[ -f "$pkg_json" ]] && scan_package_json "$pkg_json"
