#!/usr/bin/env bash
# © 2026 Sooke Software — Ted Neustaedter.
# Licensed under the GNU General Public License, version 3 or later.
#
# scan-for-credential-theft-behavior.sh — scans a single folder
# (non-recursive) for local heuristic indicators of credential collection,
# token harvesting, secret packaging, and likely exfiltration behaviour.
#
# Output: JSONL to stdout.
# Requires: jq.

set -uo pipefail

SCAN_PATH="${1:?Usage: scan-for-credential-theft-behavior.sh <scan_path> [verbosity_level]}"
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
    .env.development
    .pypirc
    .netrc
    .git-credentials
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

SENSITIVE_PATH_RULES=(
    "2|npm credential file path|(^|[^a-z0-9_])(~|\\$home|\\$\{?home\}?|%userprofile%)[/\\]\\.npmrc($|[^a-z0-9_])|(^|[^a-z0-9_])\\.npmrc($|[^a-z0-9_])"
    "2|Python publish credential path|(^|[^a-z0-9_])(~|\\$home|\\$\{?home\}?|%userprofile%)[/\\]\\.pypirc($|[^a-z0-9_])|(^|[^a-z0-9_])\\.pypirc($|[^a-z0-9_])"
    "2|netrc credential path|(^|[^a-z0-9_])(~|\\$home|\\$\{?home\}?|%userprofile%)[/\\]\\.netrc($|[^a-z0-9_])|(^|[^a-z0-9_])\\.netrc($|[^a-z0-9_])"
    "2|git credential store path|(^|[^a-z0-9_])(~|\\$home|\\$\{?home\}?|%userprofile%)[/\\]\\.git-credentials($|[^a-z0-9_])|(^|[^a-z0-9_])\\.git-credentials($|[^a-z0-9_])"
    "2|SSH credential store path|(~|\\$home|\\$\{?home\}?|%userprofile%)[/\\]\\.ssh([/\\]|$)|authorized_keys|known_hosts|id_rsa|id_ed25519"
    "2|AWS credential store path|(~|\\$home|\\$\{?home\}?|%userprofile%)[/\\]\\.aws([/\\](credentials|config))?"
    "2|Azure credential store path|(~|\\$home|\\$\{?home\}?|%userprofile%)[/\\]\\.azure([/\\]|$)|%appdata%[/\\]azure"
    "2|GCP credential store path|(~|\\$home|\\$\{?home\}?|%userprofile%)[/\\]\\.config[/\\]gcloud([/\\]|$)|google[/\\]cloud"
    "2|VS Code global storage path|%appdata%[/\\]code[/\\]user[/\\]globalstorage"
    "2|Kubernetes credential path|(^|[^a-z0-9_])(kubeconfig|\\.kube[/\\]config)($|[^a-z0-9_])"
    "2|Docker credential config path|(~|\\$home|\\$\{?home\}?|%userprofile%)[/\\]\\.docker[/\\]config\\.json"
    "2|browser secret storage path|login data|cookies|local state|google[/\\]chrome[/\\]user data|chromium[/\\]user data|firefox[/\\]profiles"
)

SECRET_ENV_RULES=(
    "1|well-known secret environment variable|(^|[^a-z0-9_])(github_token|gh_token|npm_token|node_auth_token|aws_access_key_id|aws_secret_access_key|aws_session_token|azure_client_secret|azure_tenant_id|google_application_credentials|pip_index_url|pip_extra_index_url|twine_username|twine_password|vss_nuget_external_feed_endpoints|ci_job_token|docker_auth_config|kubeconfig|ssh_auth_sock)($|[^a-z0-9_])"
    "1|package or cloud secret environment prefix|(^|[^a-z0-9_])(jfrog_[a-z0-9_]+|artifactory_[a-z0-9_]+|gcp_[a-z0-9_]+)($|[^a-z0-9_])"
)

SECRET_READ_RULES=(
    "2|direct file read primitive|get-content|readalltext|file\\.readalltext|fs\\.readfile(sync)?|os\\.readfile|open[[:space:]]*\\([^\\)]*\\)\\.read"
    "2|shell read of likely secret store|cat[[:space:]]+[^\r\n]*(\\.npmrc|\\.pypirc|\\.netrc|\\.git-credentials|\\.ssh|\\.aws|kubeconfig)|type[[:space:]]+[^\r\n]*(\\.npmrc|\\.pypirc|\\.netrc|\\.git-credentials|\\.ssh|\\.aws|kubeconfig)"
    "1|filesystem enumeration primitive|glob|find|findfirstfile|get-childitem|readdir|enumeratefiles|walkdir|scandir"
)

ENV_ACCESS_RULES=(
    "2|environment secret enumeration|process\\.env|os\\.environ|getenv[[:space:]]*\\(|\\[environment\\]::getenvironmentvariable|printenv|env[[:space:]]*\\|[[:space:]]*grep|set[[:space:]]*\\|[[:space:]]*findstr"
)

_b64='base''64'
PACKAGING_RULES=(
    "2|copying likely secret material|copy-item|copyfile|copy[[:space:]]+[^\r\n]*(\\.ssh|\\.aws|\\.npmrc|\\.pypirc|\\.netrc|\\.git-credentials|kubeconfig)|cp[[:space:]]+[^\r\n]*(\\.ssh|\\.aws|\\.npmrc|\\.pypirc|\\.netrc|\\.git-credentials|kubeconfig)"
    "2|archiving or compressing data|compress-archive|tar[[:space:]]+-|zip[[:space:]]+-|7z[[:space:]]+a|archive"
    "2|encoding likely secret data|to${_b64}string|from${_b64}string|${_b64}"
)

_iwr='invoke-web''request'
_irm='invoke-rest''method'
_webhook='web''hook\.site'
_requestbin='request''bin'
_discord='disc''ord\.com/api/web''hooks'
_telegram='api\.tele''gram\.org/bot'
OUTBOUND_RULES=(
    "3|HTTP upload or outbound request primitive|\\bcurl\\b|\\bwget\\b|requests\\.(post|put)[[:space:]]*\\(|axios\\.(post|put)[[:space:]]*\\(|fetch[[:space:]]*\\("
    "3|PowerShell outbound request primitive|${_iwr}|${_irm}"
    "2|file transfer primitive|\\bscp\\b|\\bsftp\\b|\\bftp\\b|upload"
    "3|webhook or callback endpoint|${_discord}|${_webhook}|${_requestbin}|${_telegram}"
    "3|raw IP callback URL|https?://[0-9]{1,3}(\\.[0-9]{1,3}){3}"
)

_ps='power''shell'
_pwsh='pw''sh'
_start='start''-process'
_child='child''_''process'
_spawn='sp''awn'
_exec='ex''ec'
_eval='ev''al'
_atob='at''ob'
EXECUTION_RULES=(
    "1|encoded shell execution|${_ps}[[:space:]]+-e(n|nc)\\b|${_pwsh}[[:space:]]+-e(n|nc)\\b"
    "1|inline shell execution|node[[:space:]]+-e\\b|python[[:space:]]+-c\\b|bash[[:space:]]+-c\\b|sh[[:space:]]+-c\\b|cmd[[:space:]]*/c\\b"
    "1|script execution helper|${_start}|subprocess|${_child}|${_spawn}[[:space:]]*\\(|${_exec}[[:space:]]*\\(|${_eval}[[:space:]]*\\(|${_atob}[[:space:]]*\\("
    "1|hidden shell execution|-windowstyle[[:space:]]+hidden|-w[[:space:]]+hidden"
)

THEFT_KEYWORD_RULES=(
    "1|explicit theft-oriented wording|steal|credential[[:space:]]+dump|secrets?[[:space:]]+dump|token[[:space:]]+dump|harvest|exfil|gather[[:space:]]+credentials|upload[[:space:]]+secrets|export[[:space:]]+env"
)

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
    local name="$1" ext=""
    local entry
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
            get_rule_hits "$value" "${SENSITIVE_PATH_RULES[@]}"
            get_rule_hits "$value" "${SECRET_ENV_RULES[@]}"
            get_rule_hits "$value" "${SECRET_READ_RULES[@]}"
            get_rule_hits "$value" "${ENV_ACCESS_RULES[@]}"
            get_rule_hits "$value" "${PACKAGING_RULES[@]}"
            get_rule_hits "$value" "${OUTBOUND_RULES[@]}"
            get_rule_hits "$value" "${EXECUTION_RULES[@]}"
            get_rule_hits "$value" "${THEFT_KEYWORD_RULES[@]}"
        } 2>/dev/null)"
        [[ -n "$combined" ]] && keys+=("$key")
    done
    printf '%s\n' "${keys[*]}"
}

get_recommendation() {
    case "$1" in
        HIGH)
            echo "Investigate immediately. This file combines secret access indicators with packaging or outbound behaviour consistent with credential theft."
            ;;
        Medium)
            echo "Review this file carefully. The combined heuristics suggest suspicious secret collection or token harvesting behaviour."
            ;;
        *)
            echo "Review in context. This may be benign configuration handling, but it references sensitive secrets or credential stores."
            ;;
    esac
}

analyze_file() {
    local filepath="$1" pkg_name="$2" pkg_version="$3"
    local filename="${filepath##*/}" text
    text=$(get_scan_text "$filepath")
    [[ -z "$text" && "$filename" != "package.json" ]] && return 0

    local sensitive_hits secret_env_hits secret_read_hits env_access_hits packaging_hits outbound_hits execution_hits keyword_hits
    sensitive_hits=$(get_rule_hits "$text" "${SENSITIVE_PATH_RULES[@]}")
    secret_env_hits=$(get_rule_hits "$text" "${SECRET_ENV_RULES[@]}")
    secret_read_hits=$(get_rule_hits "$text" "${SECRET_READ_RULES[@]}")
    env_access_hits=$(get_rule_hits "$text" "${ENV_ACCESS_RULES[@]}")
    packaging_hits=$(get_rule_hits "$text" "${PACKAGING_RULES[@]}")
    outbound_hits=$(get_rule_hits "$text" "${OUTBOUND_RULES[@]}")
    execution_hits=$(get_rule_hits "$text" "${EXECUTION_RULES[@]}")
    keyword_hits=$(get_rule_hits "$text" "${THEFT_KEYWORD_RULES[@]}")

    local sensitive_count secret_env_count secret_read_count env_access_count packaging_count outbound_count execution_count keyword_count
    sensitive_count=$(get_hit_count "$sensitive_hits")
    secret_env_count=$(get_hit_count "$secret_env_hits")
    secret_read_count=$(get_hit_count "$secret_read_hits")
    env_access_count=$(get_hit_count "$env_access_hits")
    packaging_count=$(get_hit_count "$packaging_hits")
    outbound_count=$(get_hit_count "$outbound_hits")
    execution_count=$(get_hit_count "$execution_hits")
    keyword_count=$(get_hit_count "$keyword_hits")

    local has_secret_source=false has_collection_signal=false has_theft_signal=false
    (( sensitive_count > 0 || secret_env_count > 0 )) && has_secret_source=true
    (( secret_read_count > 0 || env_access_count > 0 || packaging_count > 0 )) && has_collection_signal=true
    if (( keyword_count > 0 )) && { $has_collection_signal || (( outbound_count > 0 )); }; then
        has_theft_signal=true
    fi

    if ! $has_secret_source && ! $has_theft_signal; then
        return 0
    fi

    local score=0
    (( score += $(get_hit_weight "$sensitive_hits") ))
    (( score += $(get_hit_weight "$secret_env_hits") ))
    (( score += $(get_hit_weight "$secret_read_hits") ))
    (( score += $(get_hit_weight "$env_access_hits") ))
    (( score += $(get_hit_weight "$packaging_hits") ))
    (( score += $(get_hit_weight "$outbound_hits") ))
    (( score += $(get_hit_weight "$execution_hits") ))
    (( score += $(get_hit_weight "$keyword_hits") ))

    (( sensitive_count >= 2 )) && (( score += 2 ))
    (( secret_env_count >= 2 )) && (( score += 1 ))
    (( sensitive_count > 0 && secret_read_count > 0 )) && (( score += 2 ))
    (( secret_env_count > 0 && env_access_count > 0 )) && (( score += 2 ))
    (( packaging_count > 0 )) && $has_secret_source && (( score += 3 ))
    if (( execution_count > 0 )) && { (( outbound_count > 0 )) || $has_collection_signal; }; then
        (( score += 2 ))
    fi

    local script_context=""
    if [[ "$filename" == "package.json" ]]; then
        script_context=$(get_package_script_context "$filepath")
        [[ -n "$script_context" ]] && $has_secret_source && (( score += 2 ))
    elif [[ "$filename" == "Dockerfile" || "$filename" == "Makefile" || "$filename" == "Jenkinsfile" ]]; then
        if $has_secret_source && { (( outbound_count > 0 )) || $has_collection_signal; }; then
            (( score += 2 ))
        fi
    fi

    local strong_exfil=false
    if (( outbound_count > 0 )) && {
        (( sensitive_count > 0 && secret_read_count > 0 )) ||
        (( secret_env_count > 0 && env_access_count > 0 )) ||
        (( packaging_count > 0 )) && $has_secret_source;
    }; then
        strong_exfil=true
    fi

    local high_confidence=false
    if $strong_exfil || {
        (( outbound_count > 0 )) &&
        $has_secret_source &&
        $has_collection_signal &&
        { (( execution_count > 0 )) || (( keyword_count > 0 )); };
    } || {
        (( packaging_count > 0 && outbound_count > 0 )) && $has_secret_source;
    }; then
        high_confidence=true
    fi

    local severity="Info"
    if $high_confidence; then
        severity="HIGH"
    elif (( score >= 4 )); then
        severity="Medium"
    fi

    local type="CredentialTheftBehavior"
    if [[ "$filename" == "package.json" && -n "$script_context" ]]; then
        type="CredentialTheftLifecycle"
    elif [[ "$severity" == "Info" ]]; then
        type="CredentialAccessIndicator"
    fi

    local -a indicator_parts=()
    (( sensitive_count > 0 )) && indicator_parts+=("secret-store references")
    (( secret_env_count > 0 )) && indicator_parts+=("secret env names")
    (( secret_read_count + env_access_count > 0 )) && indicator_parts+=("credential access logic")
    (( packaging_count > 0 )) && indicator_parts+=("packaging or encoding")
    (( outbound_count > 0 )) && indicator_parts+=("outbound transfer")
    (( execution_count > 0 )) && indicator_parts+=("script execution")
    (( keyword_count > 0 )) && indicator_parts+=("theft wording")
    local indicator_summary="$(printf '%s\n' "${indicator_parts[@]}" | awk '!seen[$0]++' | paste -sd ', ' -)"

    local -a evidence_parts=()
    local labels
    labels=$(get_hit_labels "$sensitive_hits")
    [[ -n "$labels" ]] && evidence_parts+=("Paths: $labels")
    labels=$(get_hit_labels "$secret_env_hits")
    [[ -n "$labels" ]] && evidence_parts+=("Env: $labels")
    labels=$(get_hit_labels "$({ printf '%s\n' "$secret_read_hits"; printf '%s\n' "$env_access_hits"; } | sed '/^$/d')")
    [[ -n "$labels" ]] && evidence_parts+=("Access: $labels")
    labels=$(get_hit_labels "$packaging_hits")
    [[ -n "$labels" ]] && evidence_parts+=("Packaging: $labels")
    labels=$(get_hit_labels "$outbound_hits")
    [[ -n "$labels" ]] && evidence_parts+=("Outbound: $labels")
    labels=$(get_hit_labels "$execution_hits")
    [[ -n "$labels" ]] && evidence_parts+=("Execution: $labels")
    labels=$(get_hit_labels "$keyword_hits")
    [[ -n "$labels" ]] && evidence_parts+=("Keywords: $labels")
    [[ -n "$script_context" ]] && evidence_parts+=("Scripts: ${script_context// /, }")
    local evidence_summary="$(printf '%s\n' "${evidence_parts[@]}" | paste -sd '|' - | sed 's/|/ | /g')"

    emit_finding \
        "$severity" \
        "$type" \
        "$filepath" \
        "$pkg_name" \
        "$pkg_version" \
        "Credential theft heuristic score $score - $indicator_summary" \
        "$evidence_summary" \
        "$(get_recommendation "$severity")"
}

IFS=$'\t' read -r PACKAGE_NAME PACKAGE_VERSION < <(get_project_identity)

while IFS= read -r -d '' filepath; do
    test_is_target_file "${filepath##*/}" || continue
    analyze_file "$filepath" "$PACKAGE_NAME" "$PACKAGE_VERSION"
done < <(find "$SCAN_PATH" -mindepth 1 -maxdepth 1 -type f -print0 2>/dev/null)