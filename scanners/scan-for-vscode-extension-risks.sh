#!/usr/bin/env bash
# © 2026 Sooke Software — Ted Neustaedter.
# Licensed under the GNU General Public License, version 3 or later.
#
# scan-for-vscode-extension-risks.sh — scans a single folder
# (non-recursive) for local heuristic indicators of risky VS Code / Open VSX
# extension manifest settings, lifecycle scripts, workspace access, secret
# access, outbound traffic, and persistence-adjacent behaviour.
#
# Output: JSONL to stdout.
# Requires: jq.

set -uo pipefail

SCAN_PATH="${1:?Usage: scan-for-vscode-extension-risks.sh <scan_path> [verbosity_level]}"
VERBOSITY="${2:-0}"

if ! command -v jq &>/dev/null; then
    echo "ERROR: jq is required. Install it with your package manager (e.g. apt install jq, brew install jq)." >&2
    exit 1
fi

EXACT_TARGET_FILES=(
    package.json
    package-lock.json
    npm-shrinkwrap.json
    extension.js
    extension.ts
    main.js
    main.ts
    README.md
    CHANGELOG.md
    LICENSE
    .vscodeignore
    .npmrc
    .env
    .env.local
)

TARGET_EXTENSIONS=(
    .js .cjs .mjs .ts
    .json .yml .yaml
    .ps1 .sh
)

MANIFEST_INDICATOR_KEYS=(
    main
    activationEvents
    contributes
    publisher
    displayName
    categories
    extensionKind
    browser
    capabilities
    enabledApiProposals
    extensionDependencies
    extensionPack
)

LIFECYCLE_KEYS=(preinstall install postinstall prepare prepublishOnly vscode:prepublish compile watch package)

_iwr='invoke-web''request'
_irm='invoke-rest''method'
_iex='invoke-exp''ression|(^|[^a-z])i''ex([^a-z]|$)'
_ps='power''shell'
_pwsh='pw''sh'
_bits='bits''admin'
_mshta='ms''hta'
_rundll='run''dll32'
_regsvr='reg''svr32'
_cert='cert''util'
_start='start''-process'
_from_b64='from''base''64string'
_b64='base''64'
_eval='ev''al'
_atob='at''ob'
_function='fu''nction'
_child='child''_''process'
_spawn='sp''awn'
_exec='ex''ec'
_discord='disc''ord\.com/api/web''hooks'
_telegram='api\.tele''gram\.org/bot'
_webhook_site='web''hook\.site'
_requestbin='request''bin'
_global_storage='global''storage'
_workspace_storage='workspace''storage'
_home_refs='\$home|\$env:homepath'

LIFECYCLE_RULES=(
    "2|shell downloader primitive|\\bcurl\\b|\\bwget\\b"
    "2|PowerShell downloader primitive|${_iwr}|${_irm}|(^|[^a-z])iwr([^a-z]|$)"
    "3|system execution utility|${_cert}|${_bits}|${_mshta}|${_rundll}|${_regsvr}"
    "3|encoded shell launch|${_ps}[[:space:]]+-e(n|nc)\\b|${_pwsh}[[:space:]]+-e(n|nc)\\b"
    "2|inline command launch|node[[:space:]]+-e\\b|bash[[:space:]]+-c\\b|sh[[:space:]]+-c\\b|cmd[[:space:]]*/c\\b"
    "3|dynamic execution helper|${_eval}[[:space:]]*\\(|${_function}[[:space:]]*\\(|${_exec}[[:space:]]*\\(|${_spawn}[[:space:]]*\\(|${_child}"
    "4|remote script piped to shell|\\bcurl\\b[^\\r\\n|]{0,200}\\|[[:space:]]*(ba|z)?sh\\b|\\bwget\\b[^\\r\\n|]{0,200}\\|[[:space:]]*(ba|z)?sh\\b"
    "4|download piped into expression|${_iwr}[^\\r\\n|]{0,200}\\|[[:space:]]*(${_iex})"
    "3|webhook or callback endpoint|${_discord}|${_telegram}|${_webhook_site}|${_requestbin}"
    "2|stealth update wording|download[[:space:]]+payload|execute[[:space:]]+silently|update[[:space:]]+silently"
)

NETWORK_RULES=(
    "3|suspicious outbound endpoint|${_discord}|${_telegram}|${_webhook_site}|${_requestbin}|ngrok|pastebin|paste\\.ee|ghostbin"
    "2|outbound request primitive|\\bcurl\\b|\\bwget\\b|axios\\.(get|post)[[:space:]]*\\(|fetch[[:space:]]*\\(|requests\\.(get|post)[[:space:]]*\\("
    "2|PowerShell outbound request|${_iwr}|${_irm}|(^|[^a-z])iwr([^a-z]|$)"
    "3|raw IP URL|https?://[0-9]{1,3}(\\.[0-9]{1,3}){3}"
    "2|payload download helper|download(string|file)?|webclient\\.download|urlretrieve"
)

SECRET_PATH_RULES=(
    "3|SSH material access|(~|%userprofile%|${_home_refs}|os\\.homedir[[:space:]]*\\(\\))[/\\]\\.ssh([/\\]|$)|authorized_keys|known_hosts|id_rsa|id_ed25519"
    "2|package or cloud secret file access|\\.npmrc|\\.git-credentials|\\.aws([/\\]|$)|\\.azure([/\\]|$)|\\.config[/\\]gcloud"
    "3|browser profile access|login data|cookies|local state|chrome[/\\]user data|firefox[/\\]profiles"
    "2|VS Code or profile storage access|appdata|%appdata%|${_global_storage}|${_workspace_storage}|user[/\\]settings\\.json"
    "2|extension storage inspection|globalstorage|workspacestorage|storage\\.json"
)

SECRET_ENV_RULES=(
    "2|developer token variable|(^|[^a-z0-9_])(github_token|npm_token|node_auth_token|ssh_auth_sock|vscode_git_askpass_[a-z0-9_]*)([^a-z0-9_]|$)"
    "2|cloud secret variable|(^|[^a-z0-9_])(aws_[a-z0-9_]+|azure_[a-z0-9_]+|google_[a-z0-9_]+)([^a-z0-9_]|$)"
    "1|environment enumeration primitive|process\\.env|\\[environment\\]::getenvironmentvariable|getenv[[:space:]]*\\("
)

VSCODE_API_RULES=(
    "2|workspace file enumeration API|vscode\\.workspace\\.findfiles"
    "2|workspace filesystem API|vscode\\.workspace\\.fs"
    "2|command execution API|vscode\\.commands\\.executecommand"
    "3|terminal automation API|vscode\\.window\\.createterminal|terminal\\.sendtext"
    "2|extension manipulation API|extensions\\.(all|getextension)|installextension"
    "2|settings modification logic|getconfiguration[[:space:]]*\\(\\)\\.update|settings\\.json"
    "1|user-profile storage access|os\\.homedir[[:space:]]*\\(|appdata|globalstorage|workspacestorage"
)

PERSISTENCE_RULES=(
    "3|persistence primitive|schtasks|crontab|launchctl|startup|runonce|registry"
    "1|temporary payload staging|temp|tmp|appdata[/\\]local[/\\]temp|%temp%"
    "2|process launch helper|${_start}|subprocess|process\\.start"
    "2|silent update wording|auto-?update|download[[:space:]]+payload|execute[[:space:]]+silently|update[[:space:]]+silently"
    "2|file write primitive|writefile(sync)?[[:space:]]*\\(|set-content|out-file|copy-item|copyfile"
)

PACKAGING_RULES=(
    "2|large encoded blob|[A-Za-z0-9+/=]{180,}"
    "2|escaped byte blob|(\\\\x[0-9A-Fa-f]{2}){24,}|(\\\\u[0-9A-Fa-f]{4}){12,}"
    "2|bundled executable reference|\\.(exe|dll|so|dylib|bin)"
    "1|review-surface exclusion|(^|[/\\])(src|test|tests|docs|\\.github)([/\\*]|$)|\\.map"
    "1|bundled artifact wording|minified|bundle|packed"
)

OBFUSCATION_RULES=(
    "2|base64 helper|${_from_b64}|\\b${_b64}\\b"
    "2|browser decode helper|${_atob}[[:space:]]*\\("
    "2|runtime evaluation|${_eval}[[:space:]]*\\(|${_function}[[:space:]]*\\("
    "2|process execution helper|${_child}|${_spawn}[[:space:]]*\\(|${_exec}[[:space:]]*\\("
    "2|string reconstruction|string\\.fromcharcode|string\\.from''charcode|charcodeat|join[[:space:]]*\\(|replace[[:space:]]*\\([^\\)]{0,120}(http|cmd|exe|dll|sh)"
    "2|fragmented string assembly|([\"\'][^\"\'\\r\\n]{1,10}[\"\'][[:space:]]*(\\+[[:space:]]*[\"\'][^\"\'\\r\\n]{1,10}[\"\'][[:space:]]*){5,})"
)

KEYWORD_RULES=(
    "1|risky wording|webhook|exfil|stealth|hidden|loader|bootstrap|secret|credential"
    "1|collection wording|collect[[:space:]]+env|${_global_storage}|${_workspace_storage}"
)

DEPENDENCY_KEYWORD_RULES=(
    "1|suspicious dependency naming|loader|bootstrap|stealth|webhook|credential|token|update"
)

EXT_IS_EXTENSION=false
EXT_MARKERS=""
EXT_ACTIVATION_HITS=""
EXT_HAS_BROAD_ACTIVATION=false
SCRIPT_KEYS=""
SCRIPT_HITS=""

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
    local entry weight label pattern rest
    for entry in "$@"; do
        weight="${entry%%|*}"
        rest="${entry#*|}"
        label="${rest%%|*}"
        pattern="${rest#*|}"
        if grep -qiE "$pattern" <<< "$text" 2>/dev/null; then
            printf '%s|%s\n' "$weight" "$label"
        fi
    done
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

join_unique_lines() {
    awk 'NF { if (seen[$0]++) next; if (count++) printf "; "; printf "%s", $0 } END { if (count) print "" }'
}

join_unique_array() {
    printf '%s\n' "$@" | join_unique_lines
}

get_recommendation() {
    case "$1" in
        HIGH)
            echo "Investigate immediately. This extension folder combines activation or extension APIs with behaviour consistent with secret access, outbound transfer, or staged execution."
            ;;
        Medium)
            echo "Review closely. The local manifest or adjacent code shows extension capabilities combined with suspicious install, network, or workspace interaction patterns."
            ;;
        *)
            echo "Review in context. This looks like an extension project with activation, capability, or workspace access patterns that warrant a manual check."
            ;;
    esac
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

get_activation_hits_from_list() {
    local activation_events="$1"
    local hits="" count=0 event lowered
    while IFS= read -r event; do
        [[ -z "$event" ]] && continue
        (( count += 1 )) || true
        lowered=$(tr '[:upper:]' '[:lower:]' <<< "$event")
        case "$lowered" in
            '*')
                hits+=$'3|wildcard activation\n'
                ;;
            onstartupfinished)
                hits+=$'2|startup activation\n'
                ;;
            workspacecontains:**)
                hits+=$'2|workspace-wide activation\n'
                ;;
            onfilesystem:*)
                hits+=$'1|filesystem activation\n'
                ;;
            onview:*)
                hits+=$'1|view activation\n'
                ;;
            oncommand:*)
                hits+=$'1|command activation\n'
                ;;
        esac
    done <<< "$activation_events"

    if (( count >= 6 )); then
        hits+=$'2|many activation events\n'
    fi

    printf '%s' "$hits"
}

load_extension_context() {
    local pkg_path="${SCAN_PATH%/}/package.json"
    local markers=() activation_events="" pkg_text="" key marker_count=0

    EXT_IS_EXTENSION=false
    EXT_MARKERS=""
    EXT_ACTIVATION_HITS=""
    EXT_HAS_BROAD_ACTIVATION=false

    if [[ -f "$pkg_path" ]]; then
        if jq -e . "$pkg_path" >/dev/null 2>&1; then
            if jq -e '.engines.vscode? // empty | tostring | length > 0' "$pkg_path" >/dev/null 2>&1; then
                markers+=("engines.vscode")
            fi

            for key in "${MANIFEST_INDICATOR_KEYS[@]}"; do
                if jq -e --arg k "$key" '.[$k]? // empty | if type=="array" then length > 0 elif type=="object" then length > 0 else tostring | length > 0 end' "$pkg_path" >/dev/null 2>&1; then
                    markers+=("$key")
                fi
            done

            activation_events=$(jq -r '.activationEvents[]? // empty' "$pkg_path" 2>/dev/null)
        else
            pkg_text=$(cat "$pkg_path" 2>/dev/null || true)
            if grep -qiE '"engines"[[:space:]]*:[[:space:]]*\{[^}]{0,300}"vscode"' <<< "$pkg_text"; then
                markers+=("engines.vscode")
            fi

            for key in "${MANIFEST_INDICATOR_KEYS[@]}"; do
                if grep -qiE '"'"$key"'"[[:space:]]*:' <<< "$pkg_text"; then
                    markers+=("$key")
                fi
            done
        fi
    fi

    for key in extension.js extension.ts main.js main.ts; do
        if [[ -f "${SCAN_PATH%/}/$key" ]]; then
            markers+=("entry file present")
            break
        fi
    done

    if (( ${#markers[@]} > 0 )); then
        EXT_MARKERS=$(printf '%s\n' "${markers[@]}" | awk 'NF && !seen[$0]++ { print }')
        marker_count=$(grep -c '.' <<< "$EXT_MARKERS" 2>/dev/null || echo 0)
    fi

    EXT_ACTIVATION_HITS=$(get_activation_hits_from_list "$activation_events")
    if grep -qE 'wildcard activation|startup activation|workspace-wide activation|many activation events' <<< "$EXT_ACTIVATION_HITS"; then
        EXT_HAS_BROAD_ACTIVATION=true
    fi

    if (( marker_count >= 2 )) || grep -qx 'engines.vscode' <<< "$EXT_MARKERS" || { grep -qx 'activationEvents' <<< "$EXT_MARKERS" && grep -qx 'contributes' <<< "$EXT_MARKERS"; }; then
        EXT_IS_EXTENSION=true
    fi
}

get_manifest_capability_hits() {
    local pkg_path="$1" hits="" powerful_count=0

    if jq -e '.enabledApiProposals? // empty | if type=="array" then length > 0 else tostring | length > 0 end' "$pkg_path" >/dev/null 2>&1; then
        hits+=$'3|experimental API proposals\n'
    fi
    if jq -e '.extensionDependencies? // empty | if type=="array" then length > 0 else tostring | length > 0 end' "$pkg_path" >/dev/null 2>&1; then
        hits+=$'1|extension dependency chaining\n'
    fi
    if jq -e '.extensionPack? // empty | if type=="array" then length > 0 else tostring | length > 0 end' "$pkg_path" >/dev/null 2>&1; then
        hits+=$'1|extension pack fan-out\n'
    fi
    if jq -e '.extensionKind? // empty | if type=="array" then length > 1 else false end' "$pkg_path" >/dev/null 2>&1; then
        hits+=$'1|multi-surface extension kind\n'
    fi
    if jq -e '.capabilities? // empty | if type=="object" then length > 0 else tostring | length > 0 end' "$pkg_path" >/dev/null 2>&1; then
        hits+=$'1|explicit capability block\n'
    fi

    powerful_count=$(jq -r '.contributes? | objects | keys[]?' "$pkg_path" 2>/dev/null | grep -ciE '^(commands|debuggers|notebooks|taskDefinitions|scm|views|menus)$' || true)
    if (( powerful_count > 0 )); then
        hits+=$'1|powerful contribution points\n'
    fi

    printf '%s' "$hits"
}

get_dependency_keyword_hits() {
    local pkg_path="$1" dep_names=""
    dep_names=$(jq -r '[.dependencies,.devDependencies,.optionalDependencies,.peerDependencies] | map(select(type=="object") | keys[]) | flatten[]?' "$pkg_path" 2>/dev/null)
    [[ -z "$dep_names" ]] && return 0
    get_rule_hits "$dep_names" "${DEPENDENCY_KEYWORD_RULES[@]}"
}

get_script_hits() {
    local text="$1"
    {
        get_rule_hits "$text" "${LIFECYCLE_RULES[@]}"
        get_rule_hits "$text" "${NETWORK_RULES[@]}"
        get_rule_hits "$text" "${SECRET_PATH_RULES[@]}"
        get_rule_hits "$text" "${SECRET_ENV_RULES[@]}"
        get_rule_hits "$text" "${PERSISTENCE_RULES[@]}"
        get_rule_hits "$text" "${OBFUSCATION_RULES[@]}"
        get_rule_hits "$text" "${KEYWORD_RULES[@]}"
    } | sed '/^$/d'
}

collect_lifecycle_script_context() {
    local pkg_path="$1" key value combined
    local -a keys=()

    SCRIPT_KEYS=""
    SCRIPT_HITS=""

    for key in "${LIFECYCLE_KEYS[@]}"; do
        value=$(jq -r --arg k "$key" '.scripts[$k] // empty' "$pkg_path" 2>/dev/null) || value=""
        [[ -z "$value" ]] && continue
        combined=$(get_script_hits "$value")
        [[ -z "$combined" ]] && continue
        keys+=("$key")
        SCRIPT_HITS+="$combined"
        [[ "$combined" == *$'\n' ]] || SCRIPT_HITS+=$'\n'
    done

    if (( ${#keys[@]} > 0 )); then
        SCRIPT_KEYS=$(join_unique_array "${keys[@]}")
    fi
}

analyze_package_manifest() {
    local filepath="$1" pkg_name="$2" pkg_version="$3"
    $EXT_IS_EXTENSION || return 0

    local text activation_hits capability_hits dependency_hits keyword_hits script_hits script_summary
    text=$(get_scan_text "$filepath")
    activation_hits="$EXT_ACTIVATION_HITS"
    capability_hits=$(get_manifest_capability_hits "$filepath")
    dependency_hits=$(get_dependency_keyword_hits "$filepath")
    collect_lifecycle_script_context "$filepath"
    script_hits="$SCRIPT_HITS"
    script_summary="$SCRIPT_KEYS"
    keyword_hits=$(get_rule_hits "$text" "${KEYWORD_RULES[@]}")

    if [[ -z "$activation_hits$capability_hits$dependency_hits$script_hits$keyword_hits" ]]; then
        return 0
    fi

    local score=0 severity="Info" type="VscodeExtensionManifestRisk" high_confidence=false
    (( score += $(get_hit_weight "$activation_hits") ))
    (( score += $(get_hit_weight "$capability_hits") ))
    (( score += $(get_hit_weight "$dependency_hits") ))
    (( score += $(get_hit_weight "$script_hits") ))
    (( score += $(get_hit_weight "$keyword_hits") ))

    $EXT_HAS_BROAD_ACTIVATION && [[ -n "$script_hits" ]] && (( score += 3 ))
    $EXT_HAS_BROAD_ACTIVATION && [[ -n "$capability_hits" ]] && (( score += 1 ))
    [[ -n "$script_hits" && -n "$capability_hits" ]] && (( score += 2 ))
    [[ -n "$script_hits" && -n "$dependency_hits" ]] && (( score += 1 ))

    if $EXT_HAS_BROAD_ACTIVATION && [[ -n "$script_hits" ]] && (( $(get_hit_weight "$script_hits") >= 6 )); then
        high_confidence=true
    fi

    if $high_confidence || (( score >= 10 )); then
        severity="HIGH"
    elif (( score >= 4 )); then
        severity="Medium"
    fi

    [[ -n "$script_hits" ]] && type="VscodeExtensionLifecycleRisk"

    local -a indicator_parts=()
    indicator_parts+=("extension manifest signals")
    [[ -n "$activation_hits" ]] && indicator_parts+=("activation risk")
    [[ -n "$script_hits" ]] && indicator_parts+=("lifecycle script abuse")
    [[ -n "$capability_hits" ]] && indicator_parts+=("powerful capability use")
    [[ -n "$dependency_hits" ]] && indicator_parts+=("dependency naming signal")
    local indicator_summary
    indicator_summary=$(printf '%s\n' "${indicator_parts[@]}" | join_unique_lines)

    local -a evidence_parts=()
    local labels manifest_summary
    manifest_summary=$(join_unique_lines <<< "$EXT_MARKERS")
    [[ -n "$manifest_summary" ]] && evidence_parts+=("Manifest: $manifest_summary")
    labels=$(get_hit_labels "$activation_hits")
    [[ -n "$labels" ]] && evidence_parts+=("Activation: $labels")
    labels=$(get_hit_labels "$capability_hits")
    [[ -n "$labels" ]] && evidence_parts+=("Capabilities: $labels")
    labels=$(get_hit_labels "$dependency_hits")
    [[ -n "$labels" ]] && evidence_parts+=("Dependencies: $labels")
    labels=$(get_hit_labels "$keyword_hits")
    [[ -n "$labels" ]] && evidence_parts+=("Keywords: $labels")
    [[ -n "$script_summary" ]] && evidence_parts+=("Scripts: $script_summary")
    local evidence_summary
    evidence_summary=$(printf '%s\n' "${evidence_parts[@]}" | paste -sd '|' - | sed 's/|/ | /g')

    emit_finding \
        "$severity" \
        "$type" \
        "$filepath" \
        "$pkg_name" \
        "$pkg_version" \
        "VS Code extension heuristic score $score - $indicator_summary" \
        "$evidence_summary" \
        "$(get_recommendation "$severity")"
}

analyze_text_file() {
    local filepath="$1" pkg_name="$2" pkg_version="$3"
    local text filename extension_code=false
    filename="${filepath##*/}"
    text=$(get_scan_text "$filepath")
    [[ -z "$text" ]] && return 0

    if grep -qiE 'require[[:space:]]*\([[:space:]]*["'"'"']vscode["'"'"']|from[[:space:]]+["'"'"']vscode["'"'"']|vscode\.' <<< "$text"; then
        extension_code=true
    fi

    if ! $EXT_IS_EXTENSION && ! $extension_code; then
        return 0
    fi

    local network_hits secret_path_hits secret_env_hits api_hits persistence_hits packaging_hits obfuscation_hits keyword_hits
    network_hits=$(get_rule_hits "$text" "${NETWORK_RULES[@]}")
    secret_path_hits=$(get_rule_hits "$text" "${SECRET_PATH_RULES[@]}")
    secret_env_hits=$(get_rule_hits "$text" "${SECRET_ENV_RULES[@]}")
    api_hits=$(get_rule_hits "$text" "${VSCODE_API_RULES[@]}")
    persistence_hits=$(get_rule_hits "$text" "${PERSISTENCE_RULES[@]}")
    packaging_hits=$(get_rule_hits "$text" "${PACKAGING_RULES[@]}")
    obfuscation_hits=$(get_rule_hits "$text" "${OBFUSCATION_RULES[@]}")
    keyword_hits=$(get_rule_hits "$text" "${KEYWORD_RULES[@]}")

    local secret_count api_count score=0 severity="Info" type="VscodeExtensionRiskIndicator" high_confidence=false
    secret_count=$(( $(get_hit_count "$secret_path_hits") + $(get_hit_count "$secret_env_hits") ))
    api_count=$(get_hit_count "$api_hits")

    if (( $(get_hit_count "$network_hits") == 0 && secret_count == 0 && api_count < 2 && $(get_hit_count "$persistence_hits") == 0 && $(get_hit_count "$packaging_hits") == 0 && $(get_hit_count "$obfuscation_hits") == 0 )); then
        return 0
    fi

    (( score += $(get_hit_weight "$network_hits") ))
    (( score += $(get_hit_weight "$secret_path_hits") ))
    (( score += $(get_hit_weight "$secret_env_hits") ))
    (( score += $(get_hit_weight "$api_hits") ))
    (( score += $(get_hit_weight "$persistence_hits") ))
    (( score += $(get_hit_weight "$packaging_hits") ))
    (( score += $(get_hit_weight "$obfuscation_hits") ))
    (( score += $(get_hit_weight "$keyword_hits") ))

    (( $(get_hit_count "$api_hits") > 0 && $(get_hit_count "$network_hits") > 0 )) && (( score += 3 ))
    (( $(get_hit_count "$api_hits") > 0 && secret_count > 0 )) && (( score += 3 ))
    (( $(get_hit_count "$network_hits") > 0 && secret_count > 0 )) && (( score += 4 ))
    (( $(get_hit_count "$persistence_hits") > 0 )) && { (( $(get_hit_count "$network_hits") > 0 )) || (( secret_count > 0 )); } && (( score += 3 ))
    (( $(get_hit_count "$obfuscation_hits") > 0 && $(get_hit_count "$network_hits") > 0 )) && (( score += 2 ))
    $EXT_HAS_BROAD_ACTIVATION && { (( $(get_hit_count "$api_hits") > 0 )) || (( $(get_hit_count "$obfuscation_hits") > 0 )); } && (( score += 2 ))
    (( $(get_hit_count "$packaging_hits") > 0 )) && { (( $(get_hit_count "$network_hits") > 0 )) || (( $(get_hit_count "$obfuscation_hits") > 0 )); } && (( score += 2 ))

    if { (( $(get_hit_count "$network_hits") > 0 && secret_count > 0 && $(get_hit_count "$api_hits") > 0 )); } || \
       { $EXT_HAS_BROAD_ACTIVATION && (( $(get_hit_count "$network_hits") > 0 && $(get_hit_count "$obfuscation_hits") > 0 )); } || \
       { (( $(get_hit_count "$persistence_hits") > 0 && $(get_hit_count "$network_hits") > 0 )); } && { (( secret_count > 0 )) || (( $(get_hit_count "$api_hits") > 0 )); }; then
        high_confidence=true
    fi

    if $high_confidence || (( score >= 10 )); then
        severity="HIGH"
    elif (( score >= 5 )); then
        severity="Medium"
    fi

    if (( $(get_hit_count "$network_hits") > 0 && secret_count > 0 )); then
        type="VscodeExtensionCredentialRisk"
    elif (( $(get_hit_count "$persistence_hits") > 0 )); then
        type="VscodeExtensionPersistenceRisk"
    elif (( $(get_hit_count "$api_hits") > 0 && $(get_hit_count "$network_hits") > 0 )); then
        type="VscodeExtensionWorkspaceRisk"
    elif (( $(get_hit_count "$packaging_hits") > 0 )); then
        type="VscodeExtensionPackagingRisk"
    elif (( $(get_hit_count "$api_hits") > 0 )); then
        type="VscodeExtensionApiRisk"
    fi

    local -a indicator_parts=()
    (( $(get_hit_count "$api_hits") > 0 )) && indicator_parts+=("extension API access")
    (( $(get_hit_count "$network_hits") > 0 )) && indicator_parts+=("outbound logic")
    (( secret_count > 0 )) && indicator_parts+=("secret access")
    (( $(get_hit_count "$persistence_hits") > 0 )) && indicator_parts+=("persistence or profile writes")
    (( $(get_hit_count "$obfuscation_hits") > 0 )) && indicator_parts+=("obfuscation or staged execution")
    (( $(get_hit_count "$packaging_hits") > 0 )) && indicator_parts+=("packaging signal")
    local indicator_summary
    indicator_summary=$(printf '%s\n' "${indicator_parts[@]}" | join_unique_lines)

    local -a evidence_parts=()
    local labels
    if $EXT_HAS_BROAD_ACTIVATION; then
        labels=$(get_hit_labels "$EXT_ACTIVATION_HITS")
        [[ -n "$labels" ]] && evidence_parts+=("Activation: $labels")
    fi
    labels=$(get_hit_labels "$api_hits")
    [[ -n "$labels" ]] && evidence_parts+=("API: $labels")
    labels=$(get_hit_labels "$network_hits")
    [[ -n "$labels" ]] && evidence_parts+=("Outbound: $labels")
    labels=$(get_hit_labels "$({ printf '%s\n' "$secret_path_hits"; printf '%s\n' "$secret_env_hits"; } | sed '/^$/d')")
    [[ -n "$labels" ]] && evidence_parts+=("Secrets: $labels")
    labels=$(get_hit_labels "$persistence_hits")
    [[ -n "$labels" ]] && evidence_parts+=("Persistence: $labels")
    labels=$(get_hit_labels "$obfuscation_hits")
    [[ -n "$labels" ]] && evidence_parts+=("Obfuscation: $labels")
    labels=$(get_hit_labels "$packaging_hits")
    [[ -n "$labels" ]] && evidence_parts+=("Packaging: $labels")
    labels=$(get_hit_labels "$keyword_hits")
    [[ -n "$labels" ]] && evidence_parts+=("Keywords: $labels")
    local evidence_summary
    evidence_summary=$(printf '%s\n' "${evidence_parts[@]}" | paste -sd '|' - | sed 's/|/ | /g')

    emit_finding \
        "$severity" \
        "$type" \
        "$filepath" \
        "$pkg_name" \
        "$pkg_version" \
        "VS Code extension heuristic score $score - $indicator_summary" \
        "$evidence_summary" \
        "$(get_recommendation "$severity")"
}

IFS=$'\t' read -r PACKAGE_NAME PACKAGE_VERSION < <(get_project_identity)
load_extension_context

if ! $EXT_IS_EXTENSION; then
    debug_log "Folder does not look like a VS Code/Open VSX extension: $SCAN_PATH"
fi

while IFS= read -r -d '' filepath; do
    test_is_target_file "${filepath##*/}" || continue
    if [[ "${filepath##*/}" == 'package.json' ]]; then
        analyze_package_manifest "$filepath" "$PACKAGE_NAME" "$PACKAGE_VERSION"
        continue
    fi
    analyze_text_file "$filepath" "$PACKAGE_NAME" "$PACKAGE_VERSION"
done < <(find "$SCAN_PATH" -mindepth 1 -maxdepth 1 -type f -print0 2>/dev/null)
