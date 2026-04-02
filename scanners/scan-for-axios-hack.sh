#!/usr/bin/env bash
# © 2026 Sooke Software — Ted Neustaedter. All rights reserved.
#
# scan-for-axios-hack.sh — scans a single directory (non-recursive) for the axios supply chain hack.
# Output: JSONL (one compact JSON object per finding) to stdout.

set -uo pipefail

SCAN_PATH="${1:?Usage: scan-for-axios-hack.sh <scan_path>}"

if ! command -v jq &>/dev/null; then
    echo "ERROR: jq is required. Install it with your package manager (e.g. apt install jq, brew install jq)." >&2
    exit 1
fi

BAD_AXIOS_VERSIONS=("1.14.1" "0.30.4")
BAD_PLAIN_CRYPTO_VERSION="4.2.1"
SUSPICIOUS_DOMAINS=("sfrclak.com")

# Emit a finding as a compact JSON object to stdout
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

# Run text-based heuristic checks against the raw file content
scan_text_indicators() {
    local text="$1" path="$2" pkg_name="$3" version="$4"
    [[ -z "$text" ]] && return 0

    for domain in "${SUSPICIOUS_DOMAINS[@]}"; do
        if echo "$text" | grep -qF "$domain"; then
            emit_finding "HIGH" "TextIndicator" "$path" "$pkg_name" "$version" \
                "Contains suspicious domain: $domain" \
                "Matched text in file" \
                "Investigate immediately."
        fi
    done

    if echo "$text" | grep -qE 'plain-crypto-js'; then
        emit_finding "HIGH" "TextIndicator" "$path" "$pkg_name" "$version" \
            "References plain-crypto-js" \
            "Matched package name text" \
            "Investigate immediately."
    fi

    if echo "$text" | grep -qE 'axios[[:space:]]*"?[[:space:]]*:[[:space:]]*"?(1\.14\.1|0\.30\.4)'; then
        emit_finding "HIGH" "TextIndicator" "$path" "$pkg_name" "$version" \
            "References known malicious axios version" \
            "Matched version text" \
            "Investigate immediately."
    fi
}

is_bad_axios_ver() {
    local ver="$1"
    for bad in "${BAD_AXIOS_VERSIONS[@]}"; do
        [[ "$ver" == "$bad" ]] && return 0
    done
    return 1
}

scan_package_json() {
    local filepath="$1"
    local text pkg_name pkg_version
    text=$(cat "$filepath" 2>/dev/null) || return 0
    pkg_name=$(jq -r '.name // ""' "$filepath" 2>/dev/null) || pkg_name=""
    pkg_version=$(jq -r '.version // ""' "$filepath" 2>/dev/null) || pkg_version=""

    scan_text_indicators "$text" "$filepath" "$pkg_name" "$pkg_version"

    # postinstall script check — read value from JSON, find line number from raw text
    local postinstall
    postinstall=$(jq -r '.scripts.postinstall // ""' "$filepath" 2>/dev/null) || postinstall=""
    if [[ -n "$postinstall" ]]; then
        local line_num line_ref=""
        line_num=$(grep -n '"postinstall"' "$filepath" 2>/dev/null | head -1 | cut -d: -f1) || line_num=""
        [[ -n "$line_num" ]] && line_ref=" (line $line_num)"
        emit_finding "Medium" "TextIndicator" "$filepath" "$pkg_name" "$pkg_version" \
            "Contains postinstall script" \
            "scripts.postinstall${line_ref}: $postinstall" \
            "Manually inspect this script to confirm it is not malicious."
    fi

    # Declared dependency checks across all dependency sections
    for section in dependencies devDependencies optionalDependencies peerDependencies; do
        local axios_ver
        axios_ver=$(jq -r --arg s "$section" '.[$s].axios // ""' "$filepath" 2>/dev/null) || axios_ver=""
        if [[ -n "$axios_ver" ]]; then
            if echo "$axios_ver" | grep -qE '(^|[^0-9])(1\.14\.1|0\.30\.4)([^0-9]|$)'; then
                emit_finding "HIGH" "DeclaredDependency" "$filepath" "axios" "$axios_ver" \
                    "Declared known malicious axios version/range" \
                    "package.json $section: axios = $axios_ver" \
                    "Investigate immediately."
            else
                emit_finding "Info" "DeclaredDependency" "$filepath" "axios" "$axios_ver" \
                    "Declared axios dependency" \
                    "package.json $section: axios = $axios_ver" \
                    "Review if needed."
            fi
        fi

        local plain_ver
        plain_ver=$(jq -r --arg s "$section" '.[$s]["plain-crypto-js"] // ""' "$filepath" 2>/dev/null) || plain_ver=""
        if [[ -n "$plain_ver" ]]; then
            if echo "$plain_ver" | grep -qE '(^|[^0-9])4\.2\.1([^0-9]|$)'; then
                emit_finding "HIGH" "DeclaredDependency" "$filepath" "plain-crypto-js" "$plain_ver" \
                    "Declared malicious plain-crypto-js version/range" \
                    "package.json $section: plain-crypto-js = $plain_ver" \
                    "Investigate immediately."
            else
                emit_finding "Medium" "DeclaredDependency" "$filepath" "plain-crypto-js" "$plain_ver" \
                    "Declared plain-crypto-js dependency" \
                    "package.json $section: plain-crypto-js = $plain_ver" \
                    "Investigate immediately."
            fi
        fi
    done
}

scan_package_lock_json() {
    local filepath="$1"
    local text
    text=$(cat "$filepath" 2>/dev/null) || return 0

    scan_text_indicators "$text" "$filepath" "" ""

    if jq -e '.packages' "$filepath" &>/dev/null; then
        local axios_ver
        axios_ver=$(jq -r '.packages["node_modules/axios"].version // ""' "$filepath" 2>/dev/null) || axios_ver=""
        if [[ -n "$axios_ver" ]]; then
            if is_bad_axios_ver "$axios_ver"; then
                emit_finding "HIGH" "LockfileDependency" "$filepath" "axios" "$axios_ver" \
                    "Lockfile includes known malicious axios version" \
                    "package-lock.json: axios@$axios_ver" \
                    "Investigate immediately."
            else
                emit_finding "Info" "LockfileDependency" "$filepath" "axios" "$axios_ver" \
                    "Lockfile includes axios" \
                    "package-lock.json: axios@$axios_ver" \
                    "Review if needed."
            fi
        fi

        local plain_ver
        plain_ver=$(jq -r '.packages["node_modules/plain-crypto-js"].version // ""' "$filepath" 2>/dev/null) || plain_ver=""
        if [[ -n "$plain_ver" ]]; then
            if [[ "$plain_ver" == "$BAD_PLAIN_CRYPTO_VERSION" ]]; then
                emit_finding "HIGH" "LockfileDependency" "$filepath" "plain-crypto-js" "$plain_ver" \
                    "Lockfile includes malicious plain-crypto-js version" \
                    "package-lock.json: plain-crypto-js@$plain_ver" \
                    "Investigate immediately."
            else
                emit_finding "Medium" "LockfileDependency" "$filepath" "plain-crypto-js" "$plain_ver" \
                    "Lockfile includes plain-crypto-js" \
                    "package-lock.json: plain-crypto-js@$plain_ver" \
                    "Investigate immediately."
            fi
        fi
    fi
}

scan_bower_json() {
    local filepath="$1"
    local text
    text=$(cat "$filepath" 2>/dev/null) || return 0

    scan_text_indicators "$text" "$filepath" "" ""

    for section in dependencies devDependencies; do
        local axios_ver
        axios_ver=$(jq -r --arg s "$section" '.[$s].axios // ""' "$filepath" 2>/dev/null) || axios_ver=""
        if [[ -n "$axios_ver" ]]; then
            if echo "$axios_ver" | grep -qE '(^|[^0-9])(1\.14\.1|0\.30\.4)([^0-9]|$)'; then
                emit_finding "HIGH" "DeclaredDependency" "$filepath" "axios" "$axios_ver" \
                    "Declared known malicious axios version/range" \
                    "bower.json $section: axios = $axios_ver" \
                    "Investigate immediately."
            else
                emit_finding "Info" "DeclaredDependency" "$filepath" "axios" "$axios_ver" \
                    "Declared axios dependency" \
                    "bower.json $section: axios = $axios_ver" \
                    "Review if needed."
            fi
        fi

        local plain_ver
        plain_ver=$(jq -r --arg s "$section" '.[$s]["plain-crypto-js"] // ""' "$filepath" 2>/dev/null) || plain_ver=""
        if [[ -n "$plain_ver" ]]; then
            if echo "$plain_ver" | grep -qE '(^|[^0-9])4\.2\.1([^0-9]|$)'; then
                emit_finding "HIGH" "DeclaredDependency" "$filepath" "plain-crypto-js" "$plain_ver" \
                    "Declared malicious plain-crypto-js version/range" \
                    "bower.json $section: plain-crypto-js = $plain_ver" \
                    "Investigate immediately."
            else
                emit_finding "Medium" "DeclaredDependency" "$filepath" "plain-crypto-js" "$plain_ver" \
                    "Declared plain-crypto-js dependency" \
                    "bower.json $section: plain-crypto-js = $plain_ver" \
                    "Investigate immediately."
            fi
        fi
    done
}

# ── Main: scan target files in the given directory only (no recursion) ────────
for filename in package.json package-lock.json bower.json; do
    filepath="${SCAN_PATH%/}/$filename"
    [[ -f "$filepath" ]] || continue
    case "$filename" in
        package.json)      scan_package_json      "$filepath" ;;
        package-lock.json) scan_package_lock_json "$filepath" ;;
        bower.json)        scan_bower_json         "$filepath" ;;
    esac
done
