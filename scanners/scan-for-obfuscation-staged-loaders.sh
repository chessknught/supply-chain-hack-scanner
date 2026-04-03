#!/usr/bin/env bash
# © 2026 Sooke Software — Ted Neustaedter.
# Licensed under the GNU General Public License, version 3 or later.
#
# scan-for-obfuscation-staged-loaders.sh — scans a single folder
# (non-recursive) for local heuristic indicators of encoded payload handling,
# staged loading, hidden execution, temp-file staging, and download-to-run flows.
#
# Output: JSONL to stdout.
# Requires: jq.

set -uo pipefail

SCAN_PATH="${1:?Usage: scan-for-obfuscation-staged-loaders.sh <scan_path> [verbosity_level]}"
VERBOSITY="${2:-0}"

if ! command -v jq &>/dev/null; then
    echo "ERROR: jq is required. Install it with your package manager (e.g. apt install jq, brew install jq)." >&2
    exit 1
fi

EXACT_TARGET_FILES=(
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
    Makefile
    Jenkinsfile
    build.gradle
    pom.xml
    Cargo.toml
    requirements.txt
    pyproject.toml
)

TARGET_EXTENSIONS=(
    .js .cjs .mjs .ts
    .py .sh .bash .zsh
    .cmd .bat .ps1 .psm1
    .json .yml .yaml
    .csproj .cs .go
)

LIFECYCLE_KEYS=(preinstall install postinstall prepare prepublish prepublishOnly prepack postpack)

_b64='base''64'
_from_b64='from''base''64string'
_atob='at''ob'
_btoa='bt''oa'
_ps='power''shell'
_pwsh='pw''sh'
_iwr='invoke-web''request'
_irm='invoke-rest''method'
_iex='invoke-exp''ression|(^|[^a-z])i''ex([^a-z]|$)'
_eval='ev''al'
_function='fu''nction'
_spawn='sp''awn'
_child='child''_''process'
_start='start''-process'
_from_char='string\.from''charcode'
_cert='cert''util'
_ps_env='\$env:'

ENCODED_RULES=(
    "2|decode helper|${_from_b64}"
    "2|PowerShell decode helper|\\[convert\\]::from${_b64}string"
    "2|shell decode flag|${_b64}[[:space:]]+-d\\b"
    "2|browser decode helper|${_atob}[[:space:]]*\\("
    "1|browser encode helper|${_btoa}[[:space:]]*\\("
    "2|buffer decode helper|buffer\\.from[[:space:]]*\\([^\\)]{0,120}${_b64}"
    "2|system decode utility|${_cert}[[:space:]]+-decode\\b"
    "2|encoded shell launch|${_ps}[[:space:]]+-e(n|nc)\\b|${_pwsh}[[:space:]]+-e(n|nc)\\b"
    "2|charcode rebuild routine|${_from_char}[[:space:]]*\\("
    "2|character reconstruction routine|\\[char\\[\\]\\]|\\bchr[[:space:]]*\\("
    "1|compression helper|gzip|zlib|inflate|decompress"
    "1|string decode routine|\\bxor\\b|decrypt|decipher|rijndael|aes"
)

DYNAMIC_RULES=(
    "2|dynamic evaluation|${_eval}[[:space:]]*\\("
    "2|runtime function build|new[[:space:]]+${_function}[[:space:]]*\\(|(^|[^a-z])${_function}[[:space:]]*\\("
    "2|PowerShell expression launch|${_iex}"
    "2|process helper|\\bexec[[:space:]]*\\(|${_spawn}[[:space:]]*\\(|${_child}"
    "2|interpreter execution helper|subprocess|os\\.system|runtime\\.getruntime\\(\\)\\.exec"
    "2|process start API|process\\.start|${_start}"
    "2|inline command launch|bash[[:space:]]+-c\\b|sh[[:space:]]+-c\\b|cmd[[:space:]]*/c\\b|node[[:space:]]+-e\\b|python[[:space:]]+-c\\b"
)

DOWNLOADER_RULES=(
    "2|web fetch utility|\\bcurl\\b|\\bwget\\b"
    "2|PowerShell web fetch|${_iwr}|${_irm}"
    "2|Python web request|requests\\.(get|post)[[:space:]]*\\("
    "2|JavaScript web request|axios\\.(get|post)[[:space:]]*\\(|fetch[[:space:]]*\\(|\\brequest[[:space:]]*\\("
    "2|download helper|download(string|file)?|urlretrieve|webclient\\.download"
    "4|pipe into shell|\\bcurl\\b[^\\r\\n|]{0,200}\\|[[:space:]]*(ba|z)?sh\\b|\\bwget\\b[^\\r\\n|]{0,200}\\|[[:space:]]*(ba|z)?sh\\b"
    "4|PowerShell pipe into expression|${_iwr}[^\\r\\n|]{0,200}\\|[[:space:]]*(${_iex})"
    "4|network response to evaluation|fetch[[:space:]]*\\([^\\)]{0,200}\\)[[:space:]]*\\.then[[:space:]]*\\([^\\)]{0,200}${_eval}"
)

HIDDEN_RULES=(
    "2|hidden window flag|-windowstyle[[:space:]]+hidden|-w[[:space:]]+hidden"
    "3|hidden process start|${_start}[^\\r\\n]{0,120}-windowstyle[[:space:]]+hidden"
    "1|background launch|nohup\\b|disown\\b|detached\\b|background"
    "1|persistence helper|schtasks|crontab|launchctl|startup"
    "1|stealth wording|execute[[:space:]]+silently|run[[:space:]]+hidden"
)

TEMP_STAGING_RULES=(
    "2|temp path reference|[/\\](tmp|var/tmp)[/\\]|%temp%|${_ps_env}temp|appdata[/\\]local[/\\]temp"
    "1|staged temp artifact|\\.(tmp|bin|dat)(''|\"|[[:space:]]|$)"
    "2|execution enable step|chmod[[:space:]]+\\+x|icacls|set-executionpolicy"
    "1|rename or move step|move-item|rename-item|\\bmv\\b|\\bren\\b"
    "2|payload write primitive|mktemp|new-item|writeallbytes|set-content|out-file"
    "1|hidden staging filename|(^|[/\\])\\.[a-z0-9_-]{4,24}\\.(tmp|bin|dat)($|[^a-z0-9])|(^|[/\\])[a-z0-9_-]{8,24}\\.(tmp|bin|dat)($|[^a-z0-9])"
)

CONSTRUCTION_RULES=(
    "2|fragmented string assembly|([\"'].[^\"'\\r\\n]{0,11}[\"'][[:space:]]*(\\+[[:space:]]*[\"'].[^\"'\\r\\n]{0,11}[\"'][[:space:]]*){5,})"
    "2|array join construction|(\\[[^\\]]{8,160}\\]|array[[:space:]]*\\()[^\\r\\n]{0,80}join[[:space:]]*\\("
    "2|disguised or rebuilt address|hxxps?://|https?://[^[:space:]\\)\"']*\\.replace[[:space:]]*\\("
    "2|character or replace rebuild|charcodeat|fromcharcode|replace[[:space:]]*\\([^\\)]{0,120}(http|cmd|exe|dll|sh)"
    "1|environment-driven command build|environment\\.|process\\.env|${_ps_env}"
)

KEYWORD_RULES=(
    "1|loader wording|(^|[^a-z])(loader|bootstrap|stub|stager|dropper|payload|shellcode|unpack|decrypt|decode)($|[^a-z])"
    "1|staged flow wording|(^|[^a-z])stage[[:space:]]*[12]|multi-?stage|second-?stage|self-?extract"
)

debug_log() {
    [[ "$VERBOSITY" == "0" ]] && return 0
    printf 'DEBUG: %s\n' "$1" >&2
}

emit_finding() {
    local severity="$1" type="$2" path="$3" pkg_name="$4" version="$5"
    local indicator="$6" evidence="$7" recommendation="$8"
    jq -cn \
        --arg severity "$severity" \
        --arg type "$type" \
        --arg path "$path" \
        --arg packageName "$pkg_name" \
        --arg version "$version" \
        --arg indicator "$indicator" \
        --arg evidence "$evidence" \
        --arg recommendation "$recommendation" \
        '{severity:$severity,type:$type,path:$path,packageName:$packageName,version:$version,indicator:$indicator,evidence:$evidence,recommendation:$recommendation}'
}

test_is_target_file() {
    local name="$1" ext="" entry
    for entry in "${EXACT_TARGET_FILES[@]}"; do
        [[ "$name" == "$entry" ]] && return 0
    done

    if [[ "$name" == *.* ]]; then
        ext=".${name##*.}"
    fi

    for entry in "${TARGET_EXTENSIONS[@]}"; do
        [[ "$ext" == "$entry" ]] && return 0
    done

    return 1
}

get_project_identity() {
    local pkg_path="${SCAN_PATH%/}/package.json"
    local pkg_name="" pkg_version=""
    if [[ -f "$pkg_path" ]]; then
        pkg_name=$(jq -r '.name // ""' "$pkg_path" 2>/dev/null) || pkg_name=""
        pkg_version=$(jq -r '.version // ""' "$pkg_path" 2>/dev/null) || pkg_version=""
    fi
    printf '%s\t%s\n' "$pkg_name" "$pkg_version"
}

get_scan_text() {
    local filepath="$1"
    awk '
        /^[[:space:]]*$/ { next }
        /^[[:space:]]*#/ { next }
        /^[[:space:]]*\/\// { next }
        /^[[:space:]]*"[0-9]+\|[^|]+\|/ { next }
        /^[[:space:]]*[A-Z_]+_RULES=\(/ { next }
        /^[[:space:]]*_[[:alnum:]_]+=.+$/ { next }
        { print }
    ' "$filepath" 2>/dev/null
}

get_rule_hits() {
    local text="$1"
    shift
    local entry weight label pattern
    for entry in "$@"; do
        weight="${entry%%|*}"
        local rest="${entry#*|}"
        label="${rest%%|*}"
        pattern="${rest#*|}"
        if grep -qiE "$pattern" <<< "$text" 2>/dev/null; then
            printf '%s|%s\n' "$weight" "$label"
        fi
    done
}

get_blob_hits() {
    local text="$1"
    local -a blob_rules=(
        "2|long encoded blob|(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{140,}={0,2}(?![A-Za-z0-9+/=])"
        "2|long hex blob|(?<![A-Fa-f0-9])[A-Fa-f0-9]{160,}(?![A-Fa-f0-9])"
        "2|escaped byte blob|(\\\\x[0-9A-Fa-f]{2}){24,}|(\\\\u[0-9A-Fa-f]{4}){12,}"
    )
    get_rule_hits "$text" "${blob_rules[@]}"
}

get_hit_weight() {
    local hits="$1"
    local sum=0 line weight
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        weight="${line%%|*}"
        (( sum += weight )) || true
    done <<< "$hits"
    echo "$sum"
}

get_hit_count() {
    local hits="$1"
    if [[ -z "$hits" ]]; then
        echo 0
    else
        grep -c '.' <<< "$hits" 2>/dev/null || echo 0
    fi
}

get_hit_labels() {
    local hits="$1" max_count="${2:-6}"
    [[ -z "$hits" ]] && return 0
    awk -F'|' '!seen[$2]++ { print $2 }' <<< "$hits" 2>/dev/null | head -n "$max_count" | paste -sd '; ' -
}

get_package_script_context() {
    local package_json_path="$1"
    local key value combined keys=()
    for key in "${LIFECYCLE_KEYS[@]}"; do
        value=$(jq -r --arg k "$key" '.scripts[$k] // ""' "$package_json_path" 2>/dev/null) || value=""
        [[ -z "$value" ]] && continue
        combined="$({
            get_rule_hits "$value" "${ENCODED_RULES[@]}"
            get_blob_hits "$value"
            get_rule_hits "$value" "${DYNAMIC_RULES[@]}"
            get_rule_hits "$value" "${DOWNLOADER_RULES[@]}"
            get_rule_hits "$value" "${HIDDEN_RULES[@]}"
            get_rule_hits "$value" "${TEMP_STAGING_RULES[@]}"
            get_rule_hits "$value" "${CONSTRUCTION_RULES[@]}"
            get_rule_hits "$value" "${KEYWORD_RULES[@]}"
        } 2>/dev/null)"
        [[ -n "$combined" ]] && keys+=("$key")
    done
    printf '%s\n' "${keys[*]}"
}

get_recommendation() {
    case "$1" in
        HIGH)
            echo "Investigate immediately. This file combines staged loading or encoded content with execution behavior consistent with a downloader or loader."
            ;;
        Medium)
            echo "Review this file closely. The combined heuristics suggest obfuscation, generated execution, or staged loading behavior worth triage."
            ;;
        *)
            echo "Review in context. The signals are weak on their own but may point to obfuscated or staged execution logic."
            ;;
    esac
}

analyze_file() {
    local filepath="$1" pkg_name="$2" pkg_version="$3"
    local filename="${filepath##*/}" text
    text=$(get_scan_text "$filepath")
    [[ -z "$text" && "$filename" != "package.json" ]] && return 0

    local encoded_hits blob_hits dynamic_hits downloader_hits hidden_hits temp_hits construction_hits keyword_hits
    encoded_hits=$(get_rule_hits "$text" "${ENCODED_RULES[@]}")
    blob_hits=$(get_blob_hits "$text")
    dynamic_hits=$(get_rule_hits "$text" "${DYNAMIC_RULES[@]}")
    downloader_hits=$(get_rule_hits "$text" "${DOWNLOADER_RULES[@]}")
    hidden_hits=$(get_rule_hits "$text" "${HIDDEN_RULES[@]}")
    temp_hits=$(get_rule_hits "$text" "${TEMP_STAGING_RULES[@]}")
    construction_hits=$(get_rule_hits "$text" "${CONSTRUCTION_RULES[@]}")
    keyword_hits=$(get_rule_hits "$text" "${KEYWORD_RULES[@]}")

    local encoded_count blob_count dynamic_count downloader_count hidden_count temp_count construction_count keyword_count
    encoded_count=$(get_hit_count "$encoded_hits")
    blob_count=$(get_hit_count "$blob_hits")
    dynamic_count=$(get_hit_count "$dynamic_hits")
    downloader_count=$(get_hit_count "$downloader_hits")
    hidden_count=$(get_hit_count "$hidden_hits")
    temp_count=$(get_hit_count "$temp_hits")
    construction_count=$(get_hit_count "$construction_hits")
    keyword_count=$(get_hit_count "$keyword_hits")

    local has_encoding=false has_dynamic=false has_downloader=false has_hidden=false has_temp=false has_construction=false has_keywords=false
    (( encoded_count + blob_count > 0 )) && has_encoding=true
    (( dynamic_count > 0 )) && has_dynamic=true
    (( downloader_count > 0 )) && has_downloader=true
    (( hidden_count > 0 )) && has_hidden=true
    (( temp_count > 0 )) && has_temp=true
    (( construction_count > 0 )) && has_construction=true
    (( keyword_count > 0 )) && has_keywords=true

    if ! $has_encoding && ! $has_dynamic && ! $has_downloader && ! $has_hidden && ! $has_temp && ! $has_construction && ! $has_keywords; then
        return 0
    fi

    local score=0
    (( score += $(get_hit_weight "$encoded_hits") ))
    (( score += $(get_hit_weight "$blob_hits") ))
    (( score += $(get_hit_weight "$dynamic_hits") ))
    (( score += $(get_hit_weight "$downloader_hits") ))
    (( score += $(get_hit_weight "$hidden_hits") ))
    (( score += $(get_hit_weight "$temp_hits") ))
    (( score += $(get_hit_weight "$construction_hits") ))
    (( score += $(get_hit_weight "$keyword_hits") ))

    (( encoded_count + blob_count >= 2 )) && (( score += 1 ))
    $has_encoding && $has_dynamic && (( score += 3 ))
    $has_downloader && $has_dynamic && (( score += 4 ))
    $has_downloader && $has_temp && (( score += 3 ))
    if $has_hidden && { $has_downloader || $has_dynamic; }; then
        (( score += 2 ))
    fi
    if $has_construction && { $has_encoding || $has_downloader || $has_dynamic; }; then
        (( score += 2 ))
    fi
    $has_temp && $has_dynamic && (( score += 2 ))

    local strong_category_count=0
    $has_encoding && (( strong_category_count += 1 ))
    $has_dynamic && (( strong_category_count += 1 ))
    $has_downloader && (( strong_category_count += 1 ))
    $has_hidden && (( strong_category_count += 1 ))
    $has_temp && (( strong_category_count += 1 ))
    $has_construction && (( strong_category_count += 1 ))
    (( strong_category_count >= 3 )) && (( score += 2 ))

    local script_context=""
    if [[ "$filename" == "package.json" ]]; then
        script_context=$(get_package_script_context "$filepath")
        if [[ -n "$script_context" ]] && { $has_encoding || $has_dynamic || $has_downloader; }; then
            (( score += 3 ))
        fi
    elif [[ "$filename" == "Dockerfile" || "$filename" == "Makefile" || "$filename" == "Jenkinsfile" ]]; then
        if { $has_downloader || $has_dynamic; } && { $has_encoding || $has_temp || $has_construction; }; then
            (( score += 2 ))
        fi
    fi

    local high_confidence=false
    if { $has_downloader && $has_dynamic; } || \
       { $has_encoding && $has_dynamic && { $has_downloader || $has_temp || $has_construction; }; } || \
       { $has_downloader && $has_temp && { $has_dynamic || $has_encoding || $has_hidden; }; } || \
       { $has_downloader && $has_hidden; } || \
       { $has_temp && $has_dynamic && $has_encoding; } || \
       { [[ -n "$script_context" ]] && { $has_downloader || { $has_encoding && $has_dynamic; }; }; }; then
        high_confidence=true
    fi

    local severity=""
    if $high_confidence; then
        severity="HIGH"
    elif $has_downloader || \
         { $has_dynamic && { $has_encoding || $has_construction || $has_temp || $has_hidden; }; } || \
         { $has_encoding && { $has_dynamic || $has_downloader || $has_construction; }; } || \
         { $has_hidden && { $has_downloader || $has_dynamic; }; } || \
         { $has_temp && { $has_downloader || $has_dynamic; }; } || \
         { [[ -n "$script_context" ]] && { $has_encoding || $has_dynamic || $has_downloader; }; }; then
        severity="Medium"
    elif (( score >= 2 || keyword_count >= 2 || blob_count > 0 )) || $has_temp || $has_construction || $has_keywords; then
        severity="Info"
    else
        return 0
    fi

    local type="ObfuscationStagedLoader"
    if [[ "$filename" == "package.json" && -n "$script_context" ]]; then
        type="ObfuscationLoaderLifecycle"
    elif [[ "$severity" == "Info" ]]; then
        type="ObfuscationIndicator"
    fi

    local -a indicator_parts=()
    $has_encoding && indicator_parts+=("encoded or packed content")
    $has_dynamic && indicator_parts+=("dynamic execution")
    $has_downloader && indicator_parts+=("network fetch")
    $has_hidden && indicator_parts+=("hidden launch")
    $has_temp && indicator_parts+=("temp staging")
    $has_construction && indicator_parts+=("rebuilt commands or addresses")
    $has_keywords && indicator_parts+=("loader wording")
    local indicator_summary
    indicator_summary="$(printf '%s\n' "${indicator_parts[@]}" | awk '!seen[$0]++' | paste -sd ', ' -)"

    local -a evidence_parts=()
    local labels
    labels=$(get_hit_labels "$({ printf '%s\n' "$encoded_hits"; printf '%s\n' "$blob_hits"; } | sed '/^$/d')")
    [[ -n "$labels" ]] && evidence_parts+=("Encoded: $labels")
    labels=$(get_hit_labels "$dynamic_hits")
    [[ -n "$labels" ]] && evidence_parts+=("Execution: $labels")
    labels=$(get_hit_labels "$downloader_hits")
    [[ -n "$labels" ]] && evidence_parts+=("Downloader: $labels")
    labels=$(get_hit_labels "$hidden_hits")
    [[ -n "$labels" ]] && evidence_parts+=("Hidden: $labels")
    labels=$(get_hit_labels "$temp_hits")
    [[ -n "$labels" ]] && evidence_parts+=("Staging: $labels")
    labels=$(get_hit_labels "$construction_hits")
    [[ -n "$labels" ]] && evidence_parts+=("Construction: $labels")
    labels=$(get_hit_labels "$keyword_hits")
    [[ -n "$labels" ]] && evidence_parts+=("Keywords: $labels")
    [[ -n "$script_context" ]] && evidence_parts+=("Scripts: ${script_context// /, }")
    local evidence_summary
    evidence_summary="$(printf '%s\n' "${evidence_parts[@]}" | paste -sd '|' - | sed 's/|/ | /g')"

    debug_log "Analyzed $filepath with score $score"

    emit_finding \
        "$severity" \
        "$type" \
        "$filepath" \
        "$pkg_name" \
        "$pkg_version" \
        "Obfuscation/staged-loader heuristic score $score - $indicator_summary" \
        "$evidence_summary" \
        "$(get_recommendation "$severity")"
}

IFS=$'\t' read -r PACKAGE_NAME PACKAGE_VERSION < <(get_project_identity)

while IFS= read -r -d '' filepath; do
    test_is_target_file "${filepath##*/}" || continue
    analyze_file "$filepath" "$PACKAGE_NAME" "$PACKAGE_VERSION"
done < <(find "$SCAN_PATH" -mindepth 1 -maxdepth 1 -type f -print0 2>/dev/null)