#!/usr/bin/env bash
# © 2026 Sooke Software — Ted Neustaedter. All rights reserved.
#
# scan-for-typosquat-packages.sh — scans a single directory (non-recursive)
# for dependency names that resemble known popular packages (typosquats,
# lookalikes, namespace confusion, separator tricks, bait-word impersonation).
# Output: JSONL (one compact JSON object per finding) to stdout.
# Requires: jq

set -uo pipefail

SCAN_PATH="${1:?Usage: scan-for-typosquat-packages.sh <scan_path> [verbosity_level]}"
VERBOSITY="${2:-0}"

if ! command -v jq &>/dev/null; then
    echo "ERROR: jq is required. Install it with your package manager." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# Well-known popular package names. One per line, lower-case.
# Extend freely — this drives all similarity checks.
# ---------------------------------------------------------------------------
KNOWN_PACKAGES=(
    # npm — UI frameworks
    react react-dom react-router react-router-dom react-redux
    vue vue-router nuxt angular next
    svelte solid-js preact lit ember

    # npm — build / tooling
    webpack vite rollup parcel esbuild turbo
    typescript ts-node babel eslint prettier jest
    mocha chai vitest swc

    # npm — runtime utilities
    axios express fastify koa hapi
    lodash underscore ramda moment dayjs date-fns
    chalk colors debug dotenv commander yargs
    uuid nanoid zod joi ajv
    socket.io ws got node-fetch superagent request
    multer formidable busboy
    jsonwebtoken bcrypt bcryptjs passport
    sequelize mongoose prisma typeorm knex
    redis ioredis mysql2 pg sqlite3
    nodemailer winston pino morgan
    body-parser cors helmet compression
    cross-env rimraf glob chokidar fs-extra
    semver minimatch micromatch
    classnames tailwindcss styled-components emotion
    redux mobx zustand recoil jotai
    graphql apollo-client apollo-server

    # Python
    requests flask django fastapi uvicorn gunicorn
    numpy pandas scipy matplotlib seaborn pillow
    torch tensorflow keras scikit-learn xgboost lightgbm
    boto3 botocore pydantic sqlalchemy alembic
    celery redis pymongo psycopg2 httpx aiohttp
    beautifulsoup4 selenium playwright scrapy
    pytest mypy black ruff isort flake8
    cryptography paramiko fabric click rich typer
    pyjwt passlib urllib3 certifi charset-normalizer idna
    jinja2 mako marshmallow attrs pydantic-settings

    # Go short names
    gin echo fiber chi gorilla

    # Rust
    serde tokio actix-web reqwest anyhow thiserror
    clap log tracing rayon chrono

    # Ruby
    rails sinatra devise rspec bundler rake capistrano
)

# ---------------------------------------------------------------------------
# Bait words used to fake legitimacy.
# ---------------------------------------------------------------------------
BAIT_WORDS=(
    official secure secured security
    trusted verified
    enterprise internal private
    core pro plus premium
    team tools util utils helper helpers
    fork fixed patched stable lts
    real true genuine legit safe
)

# ---------------------------------------------------------------------------
# Suspicious scope prefixes (lower-case).
# ---------------------------------------------------------------------------
SUSPICIOUS_SCOPES=(
    '@microsoftt' '@micros0ft' '@micro-soft' '@microsoft-'
    '@npmjs' '@npm-official' '@node-' '@nodejs-'
    '@reactjs' '@reactjs-' '@react-official' '@facebookreact'
    '@angulars' '@angular-official' '@googler'
    '@amazons' '@awss' '@aws-official'
    '@expressjs' '@vuejs-' '@nuxtjs-'
    '@babel-official' '@eslint-' '@typescript-official'
)

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
# normalize_name: strip scope, lowercase, remove separators (- _ .)
# ---------------------------------------------------------------------------
normalize_name() {
    local name="$1"
    # strip scope @foo/
    name="${name#@*/}"
    name=$(echo "$name" | sed 's|^@[^/]*/||')
    # lowercase and remove separators
    echo "$name" | tr '[:upper:]' '[:lower:]' | tr -d '_-.'
}

# ---------------------------------------------------------------------------
# levenshtein: compute edit distance between two strings.
# Pure bash — practical for short package names (≤ 40 chars).
# Prints the integer distance to stdout.
# ---------------------------------------------------------------------------
levenshtein() {
    local a="$1" b="$2"
    local la=${#a} lb=${#b}
    if   (( la == 0 )); then echo "$lb"; return
    elif (( lb == 0 )); then echo "$la"; return
    fi

    # prev row
    local prev=()
    for (( j=0; j<=lb; j++ )); do prev[$j]=$j; done

    local curr i j cost
    for (( i=1; i<=la; i++ )); do
        curr=($i)
        for (( j=1; j<=lb; j++ )); do
            if [[ "${a:i-1:1}" == "${b:j-1:1}" ]]; then cost=0; else cost=1; fi
            local sub=$(( prev[j-1] + cost ))
            local del=$(( prev[j]   + 1    ))
            local ins=$(( curr[j-1] + 1    ))
            local best=$sub
            (( del < best )) && best=$del
            (( ins < best )) && best=$ins
            curr[$j]=$best
        done
        prev=("${curr[@]}")
    done
    echo "${prev[$lb]}"
}

# ---------------------------------------------------------------------------
# is_transposition: return 0 if candidate is a single adjacent-swap of known.
# ---------------------------------------------------------------------------
is_transposition() {
    local known="$1" cand="$2"
    [[ ${#known} -ne ${#cand} ]] && return 1
    local diffs=() i
    for (( i=0; i<${#known}; i++ )); do
        [[ "${known:i:1}" != "${cand:i:1}" ]] && diffs+=($i)
        (( ${#diffs[@]} > 2 )) && return 1
    done
    if (( ${#diffs[@]} == 2 )); then
        local d0=${diffs[0]} d1=${diffs[1]}
        [[ "${known:d0:1}" == "${cand:d1:1}" && "${known:d1:1}" == "${cand:d0:1}" ]] && return 0
    fi
    return 1
}

# ---------------------------------------------------------------------------
# assess_package: analyse one dependency name.
# Prints tab-separated: SEVERITY<TAB>SIGNALS<TAB>MATCHED_KNOWN
# Prints nothing if not suspicious.
# ---------------------------------------------------------------------------
assess_package() {
    local dep="$1"
    local raw_lower signals="" matched_known="" severity=""
    raw_lower=$(echo "$dep" | tr '[:upper:]' '[:lower:]')
    local norm
    norm=$(normalize_name "$dep")

    # ── 1. Suspicious scope ───────────────────────────────────────────────
    if [[ "$dep" == @* ]]; then
        local scope
        scope=$(echo "$dep" | sed 's|/.*||' | tr '[:upper:]' '[:lower:]')
        for s in "${SUSPICIOUS_SCOPES[@]}"; do
            if [[ "$scope" == "$s"* ]]; then
                signals="${signals:+$signals | }Suspicious publisher scope: $scope"
                severity="HIGH"
                break
            fi
        done
    fi

    # ── 2. Bait word + known package name ─────────────────────────────────
    for bait in "${BAIT_WORDS[@]}"; do
        if echo "$raw_lower" | grep -qwF "$bait" 2>/dev/null; then
            for known in "${KNOWN_PACKAGES[@]}"; do
                local known_norm
                known_norm=$(normalize_name "$known")
                if echo "$norm" | grep -qF "$known_norm" 2>/dev/null ||
                   echo "$raw_lower" | grep -qF "$known" 2>/dev/null; then
                    signals="${signals:+$signals | }Bait word '$bait' combined with known package '$known'"
                    matched_known="$known"
                    [[ -z "$severity" ]] && severity="Medium"
                fi
            done
        fi
    done

    # ── 3. Separator / normalization collision ────────────────────────────
    for known in "${KNOWN_PACKAGES[@]}"; do
        local known_norm
        known_norm=$(normalize_name "$known")
        (( ${#known_norm} < 4 )) && continue
        local known_lower
        known_lower=$(echo "$known" | tr '[:upper:]' '[:lower:]')
        if [[ "$norm" == "$known_norm" && "$raw_lower" != "$known_lower" ]]; then
            signals="${signals:+$signals | }Separator collision with '$known' (normalized → '$known_norm')"
            matched_known="$known"
            [[ -z "$severity" ]] && severity="Medium"
        fi
    done

    # ── 4. Edit-distance / transposition ─────────────────────────────────
    for known in "${KNOWN_PACKAGES[@]}"; do
        local known_norm
        known_norm=$(normalize_name "$known")
        (( ${#known_norm} < 4 )) && continue
        [[ "$norm" == "$known_norm" ]] && continue

        local dist max_dist
        dist=$(levenshtein "$norm" "$known_norm")
        if (( ${#known_norm} <= 8 )); then max_dist=1; else max_dist=2; fi

        if (( dist > 0 && dist <= max_dist )); then
            # Skip if this known package is already in signals (avoid dupe)
            echo "$signals" | grep -qF "$known" && continue

            if is_transposition "$known_norm" "$norm"; then
                signals="${signals:+$signals | }Transposition of '$known' (edit distance $dist)"
            else
                signals="${signals:+$signals | }${dist}-char edit of '$known' (edit distance $dist)"
            fi
            matched_known="$known"
            if (( dist == 1 )); then
                severity="HIGH"
            elif [[ -z "$severity" ]]; then
                severity="Medium"
            fi
        fi
    done

    # ── 5. Prefix/suffix impersonation of known package ──────────────────
    for known in "${KNOWN_PACKAGES[@]}"; do
        (( ${#known} < 4 )) && continue
        local known_lower
        known_lower=$(echo "$known" | tr '[:upper:]' '[:lower:]')
        [[ "$raw_lower" == "$known_lower" ]] && continue

        local is_dangerous=false
        if [[ "$raw_lower" == "${known_lower}-"* ]] ||
           [[ "$raw_lower" == *"-${known_lower}" ]] ||
           [[ "$raw_lower" == "${known_lower}_"* ]] ||
           [[ "$raw_lower" == *"_${known_lower}" ]] ||
           [[ "$raw_lower" == "node-${known_lower}"* ]] ||
           [[ "$raw_lower" == "${known_lower}js" ]] ||
           [[ "$raw_lower" == "${known_lower}.js" ]]; then
            is_dangerous=true
        fi

        if $is_dangerous; then
            # Only flag when a bait word is also present
            local has_bait=false
            for bait in "${BAIT_WORDS[@]}"; do
                if echo "$raw_lower" | grep -qwF "$bait" 2>/dev/null; then
                    has_bait=true; break
                fi
            done
            if $has_bait && ! echo "$signals" | grep -qF "$known" 2>/dev/null; then
                signals="${signals:+$signals | }Prefix/suffix impersonation of '$known' with bait word"
                matched_known="$known"
                [[ -z "$severity" ]] && severity="Medium"
            fi
        fi
    done

    [[ -z "$signals" ]] && return

    # Count signal groups (pipe-separated)
    local sig_count
    sig_count=$(echo "$signals" | tr -cd '|' | wc -c)
    sig_count=$(( sig_count + 1 ))
    if (( sig_count >= 2 )) && [[ "$severity" != "HIGH" ]]; then
        severity="HIGH"
    fi

    printf '%s\t%s\t%s\n' "$severity" "$signals" "$matched_known"
}

# ---------------------------------------------------------------------------
# Dependency extractors — one function per manifest type.
# Each prints one package name per line to stdout.
# ---------------------------------------------------------------------------

extract_npm_json() {
    local filepath="$1"
    jq -r '
        (.dependencies // {}),
        (.devDependencies // {}),
        (.optionalDependencies // {}),
        (.peerDependencies // {})
        | keys[]
    ' "$filepath" 2>/dev/null || true
}

extract_lock_json() {
    local filepath="$1"
    jq -r '
        ((.dependencies // {}) | keys[]),
        ((.packages // {}) | keys[] | select(startswith("node_modules/")) | ltrimstr("node_modules/"))
    ' "$filepath" 2>/dev/null || true
}

extract_yarn_lock() {
    local filepath="$1"
    grep -Eo '^"?@?[a-zA-Z0-9][a-zA-Z0-9\-_\./@]*@' "$filepath" 2>/dev/null \
        | sed 's/@[^@]*$//' | sed 's/^"//' | sort -u || true
}

extract_pnpm_lock() {
    local filepath="$1"
    grep -Eo '^\s+/@?[a-zA-Z0-9][a-zA-Z0-9\-_\./@]*@' "$filepath" 2>/dev/null \
        | sed 's/@[^@]*$//' | sed 's|^\s*/||' | sort -u || true
}

extract_requirements_txt() {
    local filepath="$1"
    grep -Ev '^\s*#|^\s*-' "$filepath" 2>/dev/null \
        | grep -Eo '^[A-Za-z0-9][A-Za-z0-9\-_\.]*' | sort -u || true
}

extract_pyproject_toml() {
    local filepath="$1"
    # Pull quoted names from dependencies lists
    grep -Eo '"[A-Za-z0-9][A-Za-z0-9\-_\.]*[^"]*"' "$filepath" 2>/dev/null \
        | grep -Eo '^"[A-Za-z0-9][A-Za-z0-9\-_\.]*' | tr -d '"' | sort -u || true
}

extract_pipfile() {
    local filepath="$1"
    awk '/^\[(packages|dev-packages)\]/{found=1; next} /^\[/{found=0} found && /^[A-Za-z0-9]/{print $1}' \
        "$filepath" 2>/dev/null | tr -d '"' | sort -u || true
}

extract_setup_py() {
    local filepath="$1"
    grep -Eo '"[A-Za-z0-9][A-Za-z0-9\-_\.]+[^"]*"' "$filepath" 2>/dev/null \
        | grep -Eo '"[A-Za-z0-9][A-Za-z0-9\-_\.]*' | tr -d '"' | sort -u || true
}

extract_go_mod() {
    local filepath="$1"
    # Extract the last "/" segment from "require module/path vX.Y.Z" lines
    grep -E '^\s+[a-zA-Z0-9][a-zA-Z0-9.\-_/]+\s+v[0-9]' "$filepath" 2>/dev/null \
        | awk '{print $1}' | awk -F'/' '{print $NF}' | sort -u || true
}

extract_cargo_toml() {
    local filepath="$1"
    awk '/^\[.*dependencies/{found=1; next} /^\[/{found=0} found && /^[a-zA-Z0-9]/{print $1}' \
        "$filepath" 2>/dev/null | tr -d '"' | sort -u || true
}

extract_gemfile() {
    local filepath="$1"
    grep -E "^\s*gem\s+['\"]" "$filepath" 2>/dev/null \
        | grep -Eo "['\"][A-Za-z0-9][A-Za-z0-9\-_\.]*['\"]" \
        | tr -d "'\""| head -1 | sort -u || true
    # More robust: grab just the gem name (first quoted string per line)
    grep -E "^\s*gem\s+['\"]" "$filepath" 2>/dev/null \
        | sed "s/.*gem\s*['\"]//;s/['\"].*//" | sort -u || true
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

# Track already-reported package names; value = current severity.
# We re-emit a finding escalated to HIGH if the same name appears in
# multiple dependency files in the same folder.
declare -A seen_packages=()
declare -A seen_severity=()

TARGET_FILES=(
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
    go.mod
    Cargo.toml
    Gemfile
)

for target_file in "${TARGET_FILES[@]}"; do
    filepath="${SCAN_PATH%/}/${target_file}"
    [[ -f "$filepath" ]] || continue

    # Extract dep names into a temp variable
    dep_names=""
    case "$target_file" in
        package.json)          dep_names=$(extract_npm_json    "$filepath") ;;
        package-lock.json|npm-shrinkwrap.json)
                               dep_names=$(extract_lock_json   "$filepath") ;;
        yarn.lock)             dep_names=$(extract_yarn_lock   "$filepath") ;;
        pnpm-lock.yaml)        dep_names=$(extract_pnpm_lock   "$filepath") ;;
        requirements.txt)      dep_names=$(extract_requirements_txt "$filepath") ;;
        pyproject.toml)        dep_names=$(extract_pyproject_toml  "$filepath") ;;
        Pipfile)               dep_names=$(extract_pipfile     "$filepath") ;;
        setup.py|setup.cfg)    dep_names=$(extract_setup_py    "$filepath") ;;
        go.mod)                dep_names=$(extract_go_mod      "$filepath") ;;
        Cargo.toml)            dep_names=$(extract_cargo_toml  "$filepath") ;;
        Gemfile)               dep_names=$(extract_gemfile     "$filepath") ;;
    esac

    [[ -z "$dep_names" ]] && continue

    while IFS= read -r dep; do
        [[ -z "$dep" ]] && continue

        result=$(assess_package "$dep") || true
        [[ -z "$result" ]] && continue

        IFS=$'\t' read -r sev signals matched_known <<< "$result"

        indicator="Suspicious package '$dep'"
        [[ -n "$matched_known" ]] && indicator="$indicator (resembles '$matched_known')"
        evidence="${signals} [in ${target_file}]"

        case "$sev" in
            HIGH)   rec="Investigate immediately — '$dep' may be a typosquat or dependency-confusion attack. Remove and verify the intended package." ;;
            Medium) rec="Manually verify '$dep' is the intended dependency and not a lookalike package." ;;
            *)      rec="Review '$dep' — weak typosquat signal, low confidence." ;;
        esac

        if [[ -v seen_packages["$dep"] ]]; then
            # Already emitted — if not yet HIGH, re-emit upgraded finding
            if [[ "${seen_severity[$dep]}" != "HIGH" ]]; then
                seen_severity["$dep"]="HIGH"
                emit_finding \
                    "HIGH" \
                    "TyposquatPackage" \
                    "$filepath" \
                    "$folder_pkg_name" \
                    "$folder_pkg_version" \
                    "$indicator" \
                    "${evidence} | Also in: ${seen_packages[$dep]} (multi-file escalation)" \
                    "$rec"
            fi
        else
            seen_packages["$dep"]="$target_file"
            seen_severity["$dep"]="$sev"
            emit_finding \
                "$sev" \
                "TyposquatPackage" \
                "$filepath" \
                "$folder_pkg_name" \
                "$folder_pkg_version" \
                "$indicator" \
                "$evidence" \
                "$rec"
        fi

    done <<< "$dep_names"
done
