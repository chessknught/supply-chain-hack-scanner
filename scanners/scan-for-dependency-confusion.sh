#!/usr/bin/env bash
# © 2026 Sooke Software — Ted Neustaedter. All rights reserved.
#
# scan-for-dependency-confusion.sh — scans a single folder (non-recursive) for
# local indicators of dependency confusion risk: internal-looking unscoped package
# names, missing or misconfigured private registry pinning, Python public-fallback
# index configuration, and cross-manifest/lockfile evidence that suspicious names
# are actually resolved.
#
# Output: JSONL (one compact JSON object per finding) to stdout.
# Requires: jq (used for package.json parsing and output formatting).
#
# Usage:  scan-for-dependency-confusion.sh <scan_path> [verbosity_level]

set -uo pipefail

SCAN_PATH="${1:?Usage: scan-for-dependency-confusion.sh <scan_path> [verbosity_level]}"
VERBOSITY="${2:-0}"

if ! command -v jq &>/dev/null; then
    echo "ERROR: jq is required. Install it with your package manager (e.g. apt install jq, brew install jq)." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Internal / private naming cue words.
# A dependency whose name contains one or more of these tokens at word-level
# boundaries is considered internal-looking. Extend freely.
# ---------------------------------------------------------------------------
INTERNAL_CUE_WORDS=(
    internal private corp corporate company
    shared common platform sdk core base
    infra infrastructure auth tenant enterprise
    plugin plugins extension extensions
    service services client server api
    lib library util utils helper helpers toolkit
    framework engine runtime daemon agent
)

# ---------------------------------------------------------------------------
# Private / internal registry host patterns (lower-case substrings).
# A config or CI file containing any of these is treated as evidence of a
# private feed. Extend to cover your intranet hostnames.
# ---------------------------------------------------------------------------
PRIVATE_REGISTRY_PATTERNS=(
    artifactory jfrog
    nexus sonatype
    pkgs.dev.azure.com pkgs.visualstudio.com
    npm.pkg.github.com
    verdaccio
    proget inedo
    registry.corp registry.internal registry.local
    npm.internal pypi.internal nuget.internal
    .intranet. .internal. .corp.
)

# ---------------------------------------------------------------------------
# Environment variable names that indicate private package feed usage.
# ---------------------------------------------------------------------------
FEED_ENV_VAR_PATTERNS=(
    NPM_CONFIG_REGISTRY NPM_TOKEN NPM_AUTH_TOKEN
    PIP_INDEX_URL PIP_EXTRA_INDEX_URL PIP_TRUSTED_HOST
    POETRY_HTTP_BASIC_ POETRY_PYPI_TOKEN_
    NUGET_ENDPOINT VSS_NUGET_EXTERNAL_FEED_ENDPOINTS NUGET_TOKEN
    CODEARTIFACT_AUTH_TOKEN AWS_CODEARTIFACT_
    ARTIFACTORY_API_KEY ARTIFACTORY_TOKEN JFROG_TOKEN
    NEXUS_TOKEN NEXUS_PASSWORD
    CARGO_REGISTRIES_ CARGO_REGISTRY_TOKEN
    GEMFURY_TOKEN GEM_HOST_TOKEN
)

# ---------------------------------------------------------------------------
# Python public-fallback config keys.
# extra-index-url causes pip to consult a second, potentially public, index.
# ---------------------------------------------------------------------------
PYTHON_FALLBACK_PATTERNS=(
    extra-index-url extra_index_url --extra-index-url
)

# ---------------------------------------------------------------------------
# Manifest / lockfiles to scan for dependency names.
# ---------------------------------------------------------------------------
MANIFEST_FILES=(
    package.json
    package-lock.json
    npm-shrinkwrap.json
    yarn.lock
    pnpm-lock.yaml
    requirements.txt
    pyproject.toml
    Pipfile
    setup.py
    setup.cfg
    poetry.lock
    go.mod
    Cargo.toml
    Gemfile
    packages.config
    Directory.Packages.props
    paket.dependencies
    pom.xml
    build.gradle
    settings.gradle
)

# Subset of MANIFEST_FILES that are resolved/lockfiles.
LOCKFILE_NAMES=(
    package-lock.json
    npm-shrinkwrap.json
    yarn.lock
    pnpm-lock.yaml
    poetry.lock
)

# ---------------------------------------------------------------------------
# Config files to inspect for private registry configuration.
# ---------------------------------------------------------------------------
REGISTRY_CONFIG_FILES=(
    .npmrc
    .yarnrc
    .yarnrc.yml
    .pypirc
    pip.conf
    gradle.properties
    nuget.config
)

# ---------------------------------------------------------------------------
# CI / deployment files to inspect for private-feed environment variables.
# ---------------------------------------------------------------------------
CI_FILES=(
    Dockerfile
    docker-compose.yml
    docker-compose.yaml
    .env
    .env.local
    .env.production
)

# ---------------------------------------------------------------------------
# emit_finding: write one JSONL record to stdout.
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
# get_internal_cue_score: echo the count of INTERNAL_CUE_WORDS that appear
# as word-boundary tokens inside the dependency name (lowercased).
# ---------------------------------------------------------------------------
get_internal_cue_score() {
    local dep="$1"
    local lower count=0
    lower=$(echo "$dep" | tr '[:upper:]' '[:lower:]')
    for cue in "${INTERNAL_CUE_WORDS[@]}"; do
        if echo "$lower" | grep -qE "(^|[-_./])${cue}([-_./]|$)" 2>/dev/null; then
            (( count++ )) || true
        fi
    done
    echo "$count"
}

# ---------------------------------------------------------------------------
# get_package_prefix: echo the leading org/company-like token of a dep name.
# "contoso-auth-sdk" → "contoso".  Prints nothing if no clear prefix.
# ---------------------------------------------------------------------------
get_package_prefix() {
    local dep="$1"
    local stripped
    # Strip @scope/ if present
    stripped=$(echo "$dep" | sed 's|^@[^/]*/||')
    # First token delimited by - _ .
    local prefix
    prefix=$(echo "$stripped" | sed 's/[-_.].*$//' | tr '[:upper:]' '[:lower:]')
    # Only return prefix when name has at least one separator and prefix is 3+ chars
    if [[ ${#prefix} -ge 3 ]] && echo "$stripped" | grep -qE '[-_.]' 2>/dev/null; then
        echo "$prefix"
    fi
}

# ---------------------------------------------------------------------------
# get_registry_config_summary: scan config and CI files for private feed
# evidence. Echoes a summary string if found, nothing if absent.
# ---------------------------------------------------------------------------
get_registry_config_summary() {
    local summary="" cfpath pat envvar

    for cf in "${REGISTRY_CONFIG_FILES[@]}"; do
        cfpath="${SCAN_PATH%/}/${cf}"
        [[ -f "$cfpath" ]] || continue
        for pat in "${PRIVATE_REGISTRY_PATTERNS[@]}"; do
            if grep -qiF "$pat" "$cfpath" 2>/dev/null; then
                summary="${summary:+$summary; }${cf} → '${pat}'"
                break
            fi
        done
        # .npmrc: also look for scoped registry lines: @scope:registry=https://...
        if [[ "$cf" == ".npmrc" ]] && grep -qE '^@[a-z0-9-]+:registry\s*=' "$cfpath" 2>/dev/null; then
            if ! echo "$summary" | grep -qF ".npmrc → scoped"; then
                summary="${summary:+$summary; }.npmrc → scoped registry mapping"
            fi
        fi
    done

    for cf in "${CI_FILES[@]}"; do
        cfpath="${SCAN_PATH%/}/${cf}"
        [[ -f "$cfpath" ]] || continue
        for envvar in "${FEED_ENV_VAR_PATTERNS[@]}"; do
            if grep -qiF "$envvar" "$cfpath" 2>/dev/null; then
                summary="${summary:+$summary; }${cf} → env '${envvar}'"
                break
            fi
        done
    done

    echo "$summary"
}

# Return 0 if .npmrc has a global registry= override, else 1.
check_npmrc_global_registry() {
    local p="${SCAN_PATH%/}/.npmrc"
    [[ -f "$p" ]] || return 1
    grep -qE '^registry\s*=' "$p" 2>/dev/null
}

# Return 0 if .npmrc has any @scope:registry= pin, else 1.
check_npmrc_scope_pin() {
    local p="${SCAN_PATH%/}/.npmrc"
    [[ -f "$p" ]] || return 1
    grep -qE '^@[a-z0-9-]+:registry\s*=' "$p" 2>/dev/null
}

# ---------------------------------------------------------------------------
# Dependency extractors — one per manifest format.
# Each prints one package name per line to stdout.
# ---------------------------------------------------------------------------

extract_package_json() {
    local filepath="$1"
    jq -r '
        (.dependencies // {}),
        (.devDependencies // {}),
        (.optionalDependencies // {}),
        (.peerDependencies // {})
        | keys[]
    ' "$filepath" 2>/dev/null || true
}

extract_package_lock() {
    local filepath="$1"
    jq -r '
        ((.dependencies // {}) | keys[]),
        ((.packages // {}) | keys[] | select(startswith("node_modules/")) | ltrimstr("node_modules/"))
    ' "$filepath" 2>/dev/null || true
}

extract_yarn_lock() {
    local filepath="$1"
    grep -Eo '^"?@?[A-Za-z0-9][A-Za-z0-9\-_\./@]*@' "$filepath" 2>/dev/null \
        | sed 's/@[^@]*$//' | sed 's/^"//' | sort -u || true
}

extract_pnpm_lock() {
    local filepath="$1"
    grep -Eo '^\s+/(@?[A-Za-z0-9][A-Za-z0-9\-_\./@]*)@' "$filepath" 2>/dev/null \
        | sed 's/@[^@]*$//' | sed 's|^\s*/||' | sort -u || true
}

extract_requirements_txt() {
    local filepath="$1"
    grep -Ev '^\s*#|^\s*-|^\s*$' "$filepath" 2>/dev/null \
        | grep -Eo '^[A-Za-z0-9][A-Za-z0-9\-_\.]*' | sort -u || true
}

extract_generic_toml() {
    # Heuristic for pyproject.toml, Pipfile — extract quoted package-like names.
    local filepath="$1"
    grep -Eo '"[A-Za-z0-9][A-Za-z0-9\-_\.]+[^"]*"' "$filepath" 2>/dev/null \
        | grep -Eo '^"[A-Za-z0-9][A-Za-z0-9\-_\.]*' | tr -d '"' | sort -u || true
}

extract_setup_py() {
    local filepath="$1"
    grep -Eo "['\"][A-Za-z0-9][A-Za-z0-9\-_\.]+['\"]" "$filepath" 2>/dev/null \
        | tr -d "'\"" | sort -u || true
}

extract_poetry_lock() {
    local filepath="$1"
    grep -E '^name\s*=' "$filepath" 2>/dev/null \
        | grep -Eo '"[^"]+"' | tr -d '"' | sort -u || true
}

extract_go_mod() {
    local filepath="$1"
    grep -E '^\s+[A-Za-z0-9][A-Za-z0-9.\-_/]+\s+v[0-9]' "$filepath" 2>/dev/null \
        | awk '{print $1}' | awk -F'/' '{print $NF}' | sort -u || true
}

extract_cargo_toml() {
    local filepath="$1"
    awk '/^\[.*dependencies/{found=1; next} /^\[/{found=0} found && /^[A-Za-z0-9]/{print $1}' \
        "$filepath" 2>/dev/null | tr -d '"' | sort -u || true
}

extract_gemfile() {
    local filepath="$1"
    grep -E "^\s*gem\s+['\"]" "$filepath" 2>/dev/null \
        | sed "s/.*gem[[:space:]]*['\"]//;s/['\"].*//" | sort -u || true
}

extract_pom_xml() {
    local filepath="$1"
    grep -Eo '<artifactId>[^<]+</artifactId>' "$filepath" 2>/dev/null \
        | sed 's|<artifactId>\([^<]*\)</artifactId>|\1|' | sort -u || true
}

extract_build_gradle() {
    local filepath="$1"
    # Match 'group:artifact:version' or "group:artifact:version"
    grep -Eo "['\"][A-Za-z0-9.\-_]+:[A-Za-z0-9.\-_]+:[^'\"]*['\"]" "$filepath" 2>/dev/null \
        | grep -Eo ':[A-Za-z0-9.\-_]+:' | tr -d ':' | sort -u || true
}

extract_packages_config() {
    local filepath="$1"
    grep -oi 'id="[^"]*"' "$filepath" 2>/dev/null \
        | sed 's/^[Ii][Dd]="//;s/"$//' | sort -u || true
}

extract_package_version_props() {
    local filepath="$1"
    grep -oi 'Include="[^"]*"' "$filepath" 2>/dev/null \
        | sed 's/^[Ii][Nn][Cc][Ll][Uu][Dd][Ee]="//;s/"$//' | sort -u || true
}

extract_csproj() {
    local filepath="$1"
    grep -oi 'PackageReference[^>]*Include="[^"]*"' "$filepath" 2>/dev/null \
        | grep -oi 'Include="[^"]*"' \
        | sed 's/^[Ii][Nn][Cc][Ll][Uu][Dd][Ee]="//;s/"$//' | sort -u || true
}

extract_paket() {
    local filepath="$1"
    grep -E '^(nuget|github|http)\s+' "$filepath" 2>/dev/null \
        | awk '{print $2}' | sort -u || true
}

# ---------------------------------------------------------------------------
# Main scan body
# ---------------------------------------------------------------------------

# Associative arrays require bash 4+
declare -A primary_deps_files   # dep name  → absolute source manifest path
declare -A lockfile_deps_files  # dep name  → absolute source lockfile path
declare -A prefix_counts        # prefix    → count of primary deps sharing it
declare -A prefix_members       # prefix    → pipe-separated dep names

# ── 1. Project identity ───────────────────────────────────────────────────────
folder_pkg_name=""
folder_pkg_version=""
pkg_json_path="${SCAN_PATH%/}/package.json"
if [[ -f "$pkg_json_path" ]]; then
    folder_pkg_name=$(   jq -r '.name    // ""' "$pkg_json_path" 2>/dev/null) || folder_pkg_name=""
    folder_pkg_version=$(jq -r '.version // ""' "$pkg_json_path" 2>/dev/null) || folder_pkg_version=""
fi

# ── 2. Collect deps from all manifest and lockfiles ──────────────────────────
for manifest_file in "${MANIFEST_FILES[@]}"; do
    filepath="${SCAN_PATH%/}/${manifest_file}"
    [[ -f "$filepath" ]] || continue

    # Determine if this file is a lockfile
    is_lockfile=false
    for lf in "${LOCKFILE_NAMES[@]}"; do
        [[ "$manifest_file" == "$lf" ]] && is_lockfile=true && break
    done

    dep_names=""
    case "$manifest_file" in
        package.json)
            dep_names=$(extract_package_json "$filepath") ;;
        package-lock.json|npm-shrinkwrap.json)
            dep_names=$(extract_package_lock "$filepath") ;;
        yarn.lock)
            dep_names=$(extract_yarn_lock "$filepath") ;;
        pnpm-lock.yaml)
            dep_names=$(extract_pnpm_lock "$filepath") ;;
        requirements.txt)
            dep_names=$(extract_requirements_txt "$filepath") ;;
        pyproject.toml|Pipfile)
            dep_names=$(extract_generic_toml "$filepath") ;;
        setup.py|setup.cfg)
            dep_names=$(extract_setup_py "$filepath") ;;
        poetry.lock)
            dep_names=$(extract_poetry_lock "$filepath") ;;
        go.mod)
            dep_names=$(extract_go_mod "$filepath") ;;
        Cargo.toml)
            dep_names=$(extract_cargo_toml "$filepath") ;;
        Gemfile)
            dep_names=$(extract_gemfile "$filepath") ;;
        packages.config)
            dep_names=$(extract_packages_config "$filepath") ;;
        Directory.Packages.props)
            dep_names=$(extract_package_version_props "$filepath") ;;
        paket.dependencies)
            dep_names=$(extract_paket "$filepath") ;;
        pom.xml)
            dep_names=$(extract_pom_xml "$filepath") ;;
        build.gradle|settings.gradle)
            dep_names=$(extract_build_gradle "$filepath") ;;
    esac

    [[ -z "$dep_names" ]] && continue

    while IFS= read -r dep; do
        [[ -z "$dep" ]] && continue
        if $is_lockfile; then
            [[ -v lockfile_deps_files["$dep"] ]] || lockfile_deps_files["$dep"]="$filepath"
        else
            [[ -v primary_deps_files["$dep"] ]] || primary_deps_files["$dep"]="$filepath"
        fi
    done <<< "$dep_names"
done

# Also collect from any *.csproj files directly in the folder
for csproj in "${SCAN_PATH%/}"/*.csproj; do
    [[ -f "$csproj" ]] || continue
    dep_names=$(extract_csproj "$csproj")
    [[ -z "$dep_names" ]] && continue
    while IFS= read -r dep; do
        [[ -z "$dep" ]] && continue
        [[ -v primary_deps_files["$dep"] ]] || primary_deps_files["$dep"]="$csproj"
    done <<< "$dep_names"
done

# ── 3. Registry / feed configuration check ───────────────────────────────────
registry_summary=$(get_registry_config_summary)
has_registry_config=false
[[ -n "$registry_summary" ]] && has_registry_config=true

has_npmrc_scope_pin=false
check_npmrc_scope_pin 2>/dev/null && has_npmrc_scope_pin=true || true

has_npmrc_global_registry=false
check_npmrc_global_registry 2>/dev/null && has_npmrc_global_registry=true || true

# ── 4. Build org-prefix cluster map ──────────────────────────────────────────
for dep in "${!primary_deps_files[@]}"; do
    prefix=$(get_package_prefix "$dep")
    [[ -z "$prefix" ]] && continue
    if [[ -v prefix_counts["$prefix"] ]]; then
        (( prefix_counts["$prefix"]++ )) || true
        prefix_members["$prefix"]+="|${dep}"
    else
        prefix_counts["$prefix"]=1
        prefix_members["$prefix"]="${dep}"
    fi
done

# ── 5. Per-dep scoring and finding emission ───────────────────────────────────
finding_count=0

for dep in "${!primary_deps_files[@]}"; do
    cue_score=$(get_internal_cue_score "$dep")
    if (( cue_score == 0 )); then continue; fi

    source_path="${primary_deps_files[$dep]}"
    source_file=$(basename "$source_path")

    # Check if this dep came from an npm-ecosystem file
    is_npm_file=false
    case "$source_file" in
        package.json|package-lock.json|npm-shrinkwrap.json|yarn.lock|pnpm-lock.yaml)
            is_npm_file=true ;;
    esac

    is_unscoped=true
    [[ "$dep" == @* ]] && is_unscoped=false

    # Base severity
    severity="Info"
    if (( cue_score >= 2 )); then severity="Medium"; fi

    # Escalation A: no registry config at all in this folder
    if ! $has_registry_config; then
        if (( cue_score >= 2 )); then severity="HIGH"; else severity="Medium"; fi
    fi

    # Escalation B: npm ecosystem, unscoped, no @scope:registry= pinning in .npmrc
    if $is_npm_file && $is_unscoped && ! $has_npmrc_scope_pin; then
        if [[ "$severity" != "HIGH" ]]; then
            if (( cue_score >= 2 )); then severity="HIGH"; else severity="Medium"; fi
        fi
    fi

    # Escalation C: shares org prefix with 2+ other primary deps (naming cluster)
    prefix=$(get_package_prefix "$dep")
    shared_peers=""
    if [[ -n "$prefix" ]] && [[ -v prefix_counts["$prefix"] ]] && \
            (( prefix_counts["$prefix"] >= 2 )); then
        shared_peers=$(echo "${prefix_members[$prefix]}" \
            | tr '|' '\n' \
            | grep -v '^$' \
            | grep -vF "$dep" \
            | tr '\n' ',' \
            | sed 's/,$//')
        if [[ -n "$shared_peers" ]] && [[ "$severity" != "HIGH" ]]; then
            if $has_registry_config; then severity="Medium"; else severity="HIGH"; fi
        fi
    fi

    # Escalation D: dep also present in a lockfile (confirmed resolved)
    in_lockfile=false
    lockfile_source=""
    if [[ -v lockfile_deps_files["$dep"] ]]; then
        in_lockfile=true
        lockfile_source=$(basename "${lockfile_deps_files[$dep]}")
        [[ "$severity" != "HIGH" ]] && severity="HIGH"
    fi

    # Build evidence string
    evidence="${cue_score} internal cue word(s) matched | found in: ${source_file}"
    $in_lockfile        && evidence+=" | also resolved in lockfile: ${lockfile_source}"
    [[ -n "$shared_peers" ]] && evidence+=" | shares prefix '${prefix}' with: ${shared_peers}"
    if $has_registry_config; then
        evidence+=" | registry cfg present: ${registry_summary}"
    else
        evidence+=" | no private registry config detected in this folder"
    fi

    indicator="Internal-looking unscoped dependency '${dep}'"

    case "$severity" in
        HIGH)
            rec="Investigate '${dep}': strong internal-naming signal with insufficient feed-pinning. Confirm it cannot be resolved from a public registry. Consider scoping as @org/${dep} or adding a private-registry pin." ;;
        Medium)
            rec="Review '${dep}': name contains internal-style tokens that may resolve from a public registry. Verify your package manager config explicitly pins this name to a private feed." ;;
        *)
            rec="Low-confidence signal on '${dep}': contains internal naming cues. Confirm this is intentional and that the package is publicly available." ;;
    esac

    emit_finding "$severity" "DependencyConfusion" "$source_path" \
        "$folder_pkg_name" "$folder_pkg_version" \
        "$indicator" "$evidence" "$rec"
    (( finding_count++ )) || true
done

# ── 6. Python extra-index-url / public fallback risk ─────────────────────────
for pf in requirements.txt pyproject.toml Pipfile setup.cfg .pypirc pip.conf; do
    pfpath="${SCAN_PATH%/}/${pf}"
    [[ -f "$pfpath" ]] || continue
    for pat in "${PYTHON_FALLBACK_PATTERNS[@]}"; do
        if grep -qiF "$pat" "$pfpath" 2>/dev/null; then
            emit_finding "Medium" "DependencyConfusion" "$pfpath" \
                "$folder_pkg_name" "$folder_pkg_version" \
                "Python extra-index-url in ${pf} allows public PyPI fallback" \
                "Pattern '${pat}' found — packages absent from the primary index may fall through to public PyPI" \
                "Use only index-url (not extra-index-url) to block public fallback, or confirm that no internal package names are claimable on public PyPI."
            (( finding_count++ )) || true
            break  # one finding per file
        fi
    done
done

# ── 7. .npmrc global registry without per-scope pinning ──────────────────────
if $has_npmrc_global_registry && ! $has_npmrc_scope_pin; then
    npmrc_path="${SCAN_PATH%/}/.npmrc"
    emit_finding "Medium" "DependencyConfusion" "$npmrc_path" \
        "$folder_pkg_name" "$folder_pkg_version" \
        ".npmrc overrides global registry but has no per-scope pinning" \
        "registry= line is present but no @scope:registry= mapping — unscoped internal-looking package names may still resolve from public npm" \
        "Add per-scope registry mappings (e.g. @myorg:registry=https://your-feed) to .npmrc so internal packages are pinned to your private registry."
    (( finding_count++ )) || true
fi

# ── 8. Cargo.toml: alternate registry defined but no crate is pinned to it ───
cargo_path="${SCAN_PATH%/}/Cargo.toml"
if [[ -f "$cargo_path" ]]; then
    if grep -q '\[registries\.' "$cargo_path" 2>/dev/null && \
       ! grep -qE 'registry\s*=\s*"' "$cargo_path" 2>/dev/null; then
        emit_finding "Medium" "DependencyConfusion" "$cargo_path" \
            "$folder_pkg_name" "$folder_pkg_version" \
            "Cargo.toml defines alternate registries but no crate is pinned to one" \
            "[registries.*] section found but no registry = \"...\" assignment in [dependencies]" \
            "Pin crates to their intended private registry using registry = \"your-registry-name\" in Cargo.toml."
        (( finding_count++ )) || true
    fi
fi

# ── 9. Info: private feed config present but no suspicious dep names found ────
if $has_registry_config && (( finding_count == 0 )); then
    first_cfg=""
    for cf in "${REGISTRY_CONFIG_FILES[@]}" "${CI_FILES[@]}"; do
        cfpath="${SCAN_PATH%/}/${cf}"
        if [[ -f "$cfpath" ]]; then first_cfg="$cfpath"; break; fi
    done
    if [[ -n "$first_cfg" ]]; then
        emit_finding "Info" "DependencyConfusion" "$first_cfg" \
            "$folder_pkg_name" "$folder_pkg_version" \
            "Private registry/feed configuration detected" \
            "Config: ${registry_summary}" \
            "Confirm all dependencies are correctly scoped or pinned to the private registry to prevent public-registry fallback."
    fi
fi
