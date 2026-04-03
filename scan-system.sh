#!/usr/bin/env bash
# © 2026 Sooke Software — Ted Neustaedter. All rights reserved.
#
# scan-system.sh — scans all local mount points using registered scanner scripts.
# Requires: bash 4+, jq
#
# Interactive usage (no arguments — presents a menu):
#   ./scan-system.sh
#
# Non-interactive / CI usage:
#   ./scan-system.sh [options]
#
# Options:
#   --include-removable          Include removable drives/volumes
#   --skip-network               Exclude network mounts
#   --output-json <path>         Write JSON report to file
#   --scanners  <s1.sh,s2.sh>    Comma-separated scanner filenames to run
#   --mounts    </mnt/a,/mnt/b>  Comma-separated mount points to scan
#   --verbosity <0|1>            0=quiet (default), 1=verbose
#   --non-interactive            Force non-interactive mode (skip menu)

set -uo pipefail

# ── Bash version check ────────────────────────────────────────────────────────
if (( BASH_VERSINFO[0] < 4 )); then
    echo "ERROR: bash 4 or newer is required."
    echo "  macOS: brew install bash  (then run with /usr/local/bin/bash or /opt/homebrew/bin/bash)"
    exit 1
fi

# ── Arguments ─────────────────────────────────────────────────────────────────
INCLUDE_REMOVABLE=false
SKIP_NETWORK=false
OUTPUT_JSON=""
OPT_SCANNERS=""      # comma-separated scanner filenames (leaf names)
OPT_MOUNTS=""        # comma-separated mount points to restrict scan to
OPT_SUPPRESS=""      # comma-separated scanner leaf names to suppress console warnings for
VERBOSITY=0
NON_INTERACTIVE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --include-removable) INCLUDE_REMOVABLE=true ;;
        --skip-network)      SKIP_NETWORK=true ;;
        --output-json)       OUTPUT_JSON="${2:?--output-json requires a path}"; shift ;;
        --scanners)          OPT_SCANNERS="${2:?--scanners requires a value}"; shift ;;
        --mounts)            OPT_MOUNTS="${2:?--mounts requires a value}"; shift ;;
        --verbosity)         VERBOSITY="${2:?--verbosity requires 0 or 1}"; shift ;;
        --suppress-warnings) OPT_SUPPRESS="${2:?--suppress-warnings requires a value}"; shift ;;
        --non-interactive)   NON_INTERACTIVE=true ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; exit 1 ;;
    esac
    shift
done

# Detect interactive mode: stdin is a tty AND no scan-limiting flags were given.
IS_INTERACTIVE=false
if [[ -t 0 ]] && [[ -t 1 ]] && \
   [[ "$NON_INTERACTIVE" == "false" ]] && \
   [[ -z "$OPT_SCANNERS" ]] && \
   [[ -z "$OPT_MOUNTS" ]] && \
   [[ -z "$OPT_SUPPRESS" ]] && \
   [[ "$VERBOSITY" == "0" ]] && \
   [[ -z "$OUTPUT_JSON" ]] && \
   [[ "$INCLUDE_REMOVABLE" == "false" ]] && \
   [[ "$SKIP_NETWORK" == "false" ]]; then
    IS_INTERACTIVE=true
fi

# ── Config ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER_SCRIPTS=(
    "$SCRIPT_DIR/scanners/scan-for-axios-hack.sh"
    "$SCRIPT_DIR/scanners/scan-for-lifecycle-script-abuse.sh"
    "$SCRIPT_DIR/scanners/scan-for-suspicious-domains.sh"
    "$SCRIPT_DIR/scanners/scan-for-typosquat-packages.sh"
    "$SCRIPT_DIR/scanners/scan-for-dependency-confusion.sh"
)
EXCLUDED_DIR_NAMES=('$Recycle.Bin' 'System Volume Information')

RED=$'\033[0;31m'
YELLOW=$'\033[0;33m'
GREEN=$'\033[0;32m'
CYAN=$'\033[0;36m'
GRAY=$'\033[0;90m'
DARK_YELLOW=$'\033[0;33m'
BOLD=$'\033[1m'
RESET=$'\033[0m'

show_progress() {
    local cols msg padded
    cols=$(tput cols 2>/dev/null || echo 80)
    msg="${1:0:$(( cols - 3 ))}"
    printf -v padded "%-$(( cols - 2 ))s" "$msg"
    printf '\r\033[44;1;97m %s \033[0m' "$padded" >/dev/tty 2>/dev/null || true
}

clear_progress() {
    printf '\r\033[K' >/dev/tty 2>/dev/null || true
}

show_header() {
    local version="$1"
    clear >/dev/tty
    printf '\n' >/dev/tty
    printf "${CYAN}${BOLD}  Supply Chain Hack Scanner  v%s${RESET}\n" "$version" >/dev/tty
    printf "${CYAN}  ══════════════════════════════════════${RESET}\n" >/dev/tty
    printf "${GRAY}  © 2026 Sooke Software — Ted Neustaedter. All rights reserved.${RESET}\n" >/dev/tty
    printf "${GRAY}  https://sookesoft.com${RESET}\n" >/dev/tty
    printf '\n' >/dev/tty
}

checklist_menu() {
    local title="$1"
    local -n _items="$2"
    local -n _defs="$3"
    local count="${#_items[@]}"

    (( count == 0 )) && return 0

    local cursor=0
    local selected=()
    for (( i=0; i<count; i++ )); do
        selected[$i]="${_defs[$i]}"
    done

    while true; do
        printf '\033[2J\033[H' >/dev/tty
        printf '\n' >/dev/tty
        printf "${CYAN}  %s${RESET}\n" "$title" >/dev/tty
        printf "${CYAN}  %s${RESET}\n" "$(printf '─%.0s' $(seq 1 ${#title}))" >/dev/tty
        printf '\n' >/dev/tty
        printf "${DARK_YELLOW}  Use Up/Down to move, Space to toggle, A = all, N = none, Enter = confirm.${RESET}\n" >/dev/tty
        printf '\n' >/dev/tty

        for (( i=0; i<count; i++ )); do
            local box color pointer
            if [[ "${selected[$i]}" == "true" ]]; then box="[x]"; color="$RESET"
            else                                       box="[ ]"; color="$GRAY"; fi

            if (( i == cursor )); then
                pointer='>'
                color="$CYAN"
            else
                pointer=' '
            fi

            printf "${color}  %s %s %s${RESET}\n" "$pointer" "$box" "${_items[$i]}" >/dev/tty
        done

        local key
        IFS= read -rsn1 key </dev/tty

        if [[ "$key" == $'\x1b' ]]; then
            local rest
            IFS= read -rsn2 rest </dev/tty
            key+="$rest"
        fi

        case "$key" in
            '')
                break
                ;;
            $'\x1b[A')
                if (( cursor > 0 )); then ((cursor--)); else cursor=$(( count - 1 )); fi
                ;;
            $'\x1b[B')
                if (( cursor < count - 1 )); then ((cursor++)); else cursor=0; fi
                ;;
            ' ')
                if [[ "${selected[$cursor]}" == "true" ]]; then
                    selected[$cursor]="false"
                else
                    selected[$cursor]="true"
                fi
                ;;
            [Aa])
                for (( i=0; i<count; i++ )); do selected[$i]="true"; done
                ;;
            [Nn])
                for (( i=0; i<count; i++ )); do selected[$i]="false"; done
                ;;
        esac
    done

    for (( i=0; i<count; i++ )); do
        [[ "${selected[$i]}" == "true" ]] && echo "${_items[$i]}"
    done
}

# yes_no <prompt> <default true|false> → returns 0 for yes, 1 for no.
yes_no() {
    local prompt="$1" default="$2"
    local hint
    [[ "$default" == "true" ]] && hint="[Y/n]" || hint="[y/N]"
    printf "${DARK_YELLOW}  %s %s : ${RESET}" "$prompt" "$hint" >/dev/tty
    local r
    read -r r </dev/tty
    if [[ -z "$r" ]]; then
        [[ "$default" == "true" ]] && return 0 || return 1
    fi
    [[ "$r" =~ ^([Yy]|[Yy][Ee][Ss])$ ]] && return 0 || return 1
}

# string_prompt <prompt> <default> → echoes the entered value (or default) to stdout.
string_prompt() {
    local prompt="$1" default="$2"
    local hint
    [[ -n "$default" ]] && hint="(default: $default)" || hint="(leave blank to skip)"
    printf "${DARK_YELLOW}  %s %s : ${RESET}" "$prompt" "$hint" >/dev/tty
    local r
    read -r r </dev/tty
    [[ -z "$r" ]] && echo "$default" || echo "$r"
}

# single_choice_menu <title> <items_var_name> <default_index> → echoes chosen item to stdout.
single_choice_menu() {
    local title="$1"
    local -n _sc_items="$2"
    local default_idx="$3"
    local count="${#_sc_items[@]}"

    (( count == 0 )) && return 0

    local cursor="$default_idx"
    if (( cursor < 0 || cursor >= count )); then
        cursor=0
    fi

    while true; do
        printf '\033[2J\033[H' >/dev/tty
        printf '\n' >/dev/tty
        printf "${CYAN}  %s${RESET}\n" "$title" >/dev/tty
        printf "${CYAN}  %s${RESET}\n" "$(printf '─%.0s' $(seq 1 ${#title}))" >/dev/tty
        printf '\n' >/dev/tty
        printf "${DARK_YELLOW}  Use Up/Down to move, Enter to confirm.${RESET}\n" >/dev/tty
        printf '\n' >/dev/tty
        for (( i=0; i<count; i++ )); do
            local marker color
            if (( i == cursor )); then marker=">"; color="$CYAN"
            else                      marker=" "; color="$GRAY"; fi
            printf "${color}  %s %s${RESET}\n" "$marker" "${_sc_items[$i]}" >/dev/tty
        done

        local key
        IFS= read -rsn1 key </dev/tty
        if [[ "$key" == $'\x1b' ]]; then
            local rest
            IFS= read -rsn2 rest </dev/tty
            key+="$rest"
        fi

        case "$key" in
            '')
                echo "${_sc_items[$cursor]}"
                return
                ;;
            $'\x1b[A')
                if (( cursor > 0 )); then ((cursor--)); else cursor=$(( count - 1 )); fi
                ;;
            $'\x1b[B')
                if (( cursor < count - 1 )); then ((cursor++)); else cursor=0; fi
                ;;
        esac
    done
}

# ── Prerequisites ─────────────────────────────────────────────────────────────
if ! command -v jq &>/dev/null; then
    echo "ERROR: jq is required. Install it with your package manager (e.g. apt install jq, brew install jq)." >&2
    exit 1
fi

# ── Mount point discovery ─────────────────────────────────────────────────────
get_mount_points() {
    local os
    os="$(uname -s)"

    case "$os" in
        Linux)
            # Filter out pseudo/virtual filesystems; optionally skip network mounts
            local pseudo_re="^(tmpfs|devtmpfs|sysfs|proc|cgroup2?|hugetlbfs|mqueue|debugfs|tracefs|securityfs|pstore|bpf|autofs|overlay|squashfs|devpts|fusectl|configfs|efivarfs|ramfs)$"
            local net_re="^(nfs4?|cifs|smbfs|fuse\.sshfs|fuse\.s3fs)$"
            while IFS=' ' read -r _ target fstype _rest; do
                [[ -z "$target" || -z "$fstype" ]] && continue
                echo "$fstype" | grep -qE "$pseudo_re" && continue
                if $SKIP_NETWORK; then
                    echo "$fstype" | grep -qE "$net_re" && continue
                fi
                echo "$target"
            done < /proc/mounts 2>/dev/null | sort -u
            ;;
        Darwin)
            # Always include root; add anything mounted under /Volumes
            echo "/"
            if [[ -d /Volumes ]]; then
                while IFS= read -r -d '' vol; do
                    local volname="${vol##*/}"
                    # Skip the alias to the boot volume
                    [[ "$volname" == "Macintosh HD" ]] && continue
                    if $SKIP_NETWORK; then
                        # Best-effort: check mount output for nfs/smbfs/cifs
                        if mount | grep -q "^[^ ]* on ${vol} " ; then
                            mount | grep "^[^ ]* on ${vol} " | grep -qiE "nfs|smbfs|cifs" && continue
                        fi
                    fi
                    echo "$vol"
                done < <(find /Volumes -maxdepth 1 -mindepth 1 -type d -print0 2>/dev/null)
            fi
            ;;
        *)
            echo "/"
            ;;
    esac
}

# ── Read version ──────────────────────────────────────────────────────────────
VERSION_FILE="$SCRIPT_DIR/VERSION"
_version=$(tr -d '[:space:]' < "$VERSION_FILE" 2>/dev/null || echo "unknown")

# ── Resolve all available scanners ────────────────────────────────────────────
resolved_scanners=()
for scanner in "${SCANNER_SCRIPTS[@]}"; do
    [[ -f "$scanner" ]] || { echo "ERROR: Scanner not found: $scanner" >&2; exit 1; }
    [[ -x "$scanner" ]] || chmod +x "$scanner"
    resolved_scanners+=("$(cd "$(dirname "$scanner")" && pwd)/$(basename "$scanner")")
done

# ── Interactive menu ──────────────────────────────────────────────────────────
if $IS_INTERACTIVE; then
    show_header "$_version"

    printf "${DARK_YELLOW}  DISCLAIMER: This tool is provided as-is for informational and defensive security${RESET}\n" >/dev/tty
    printf "${DARK_YELLOW}  purposes only. It does not guarantee complete detection of all supply chain threats.${RESET}\n" >/dev/tty
    printf "${DARK_YELLOW}  Detections are based on heuristic pattern matching and may produce false positives —${RESET}\n" >/dev/tty
    printf "${DARK_YELLOW}  reported findings should not be treated as confirmed indicators of compromise without${RESET}\n" >/dev/tty
    printf "${DARK_YELLOW}  independent verification. Conversely, the absence of findings does not guarantee that${RESET}\n" >/dev/tty
    printf "${DARK_YELLOW}  a project is free from supply chain risk. Attackers may leave misleading breadcrumbs,${RESET}\n" >/dev/tty
    printf "${DARK_YELLOW}  intentionally crafted evidence, or obfuscated indicators that circumvent these checks.${RESET}\n" >/dev/tty
    printf "${DARK_YELLOW}  Results should be reviewed by a qualified security professional in the full context of${RESET}\n" >/dev/tty
    printf "${DARK_YELLOW}  your environment. Sooke Software and Ted Neustaedter accept no liability for actions${RESET}\n" >/dev/tty
    printf "${DARK_YELLOW}  taken or not taken based on this output.${RESET}\n" >/dev/tty

    scanner_labels=()
    scanner_defaults=()
    for s in "${resolved_scanners[@]}"; do
        scanner_labels+=("$(basename "$s")")
        scanner_defaults+=("true")
    done

    mapfile -t chosen_scanner_labels < <(checklist_menu "Select scanners to run" scanner_labels scanner_defaults)
    if [[ ${#chosen_scanner_labels[@]} -eq 0 ]]; then
        printf '\n  No scanners selected — nothing to do.\n' >/dev/tty
        exit 0
    fi

    mapfile -t all_mounts < <(get_mount_points)
    declare -a mount_labels=()
    declare -a mount_defaults=()
    for mp in "${all_mounts[@]}"; do
        mount_labels+=("$mp")
        mount_defaults+=("true")
    done

    mapfile -t chosen_mounts < <(checklist_menu "Select mount points to scan" mount_labels mount_defaults)
    if [[ ${#chosen_mounts[@]} -eq 0 ]]; then
        printf '\n  No mount points selected — nothing to do.\n' >/dev/tty
        exit 0
    fi

    show_header "$_version"
    printf "${CYAN}  Scan options${RESET}\n" >/dev/tty
    printf "${CYAN}  ────────────${RESET}\n\n" >/dev/tty

    verb_options=("0 — Quiet (findings only)" "1 — Verbose (per-scanner debug output)")
    verb_choice=$(single_choice_menu "Verbosity level" verb_options 0)
    [[ "$verb_choice" == 1* ]] && VERBOSITY=1 || VERBOSITY=0

    OUTPUT_JSON=$(string_prompt "Save JSON report to file path" "")

    suppress_defaults=()
    for _ in "${chosen_scanner_labels[@]}"; do suppress_defaults+=("false"); done
    mapfile -t suppressed_scanner_labels < <(checklist_menu \
        "Suppress console warnings for which scanners? (findings still saved to JSON)" \
        chosen_scanner_labels suppress_defaults)

    show_header "$_version"
    printf "${CYAN}  Ready to scan${RESET}\n" >/dev/tty
    printf "${CYAN}  ─────────────${RESET}\n\n" >/dev/tty

    printf "${RESET}  Mounts${RESET}\n" >/dev/tty
    printf "${GRAY}  ------${RESET}\n" >/dev/tty
    for mount in "${chosen_mounts[@]}"; do
        printf "${RESET}   - %s${RESET}\n" "$mount" >/dev/tty
    done
    printf '\n' >/dev/tty

    printf "${RESET}  Scanners${RESET}\n" >/dev/tty
    printf "${GRAY}  --------${RESET}\n" >/dev/tty
    for scanner_label in "${chosen_scanner_labels[@]}"; do
        scanner_suffix=""
        for suppressed_label in "${suppressed_scanner_labels[@]}"; do
            if [[ "$suppressed_label" == "$scanner_label" ]]; then
                scanner_suffix=" (no warnings)"
                break
            fi
        done
        printf "${RESET}   - %s%s${RESET}\n" "$scanner_label" "$scanner_suffix" >/dev/tty
    done
    printf '\n' >/dev/tty

    if [[ "$VERBOSITY" == "1" ]]; then
        verbosity_label="Verbose (per-scanner debug output)"
    else
        verbosity_label="Quiet (findings only)"
    fi
    printf "${RESET}  Verbosity: %s${RESET}\n" "$verbosity_label" >/dev/tty
    [[ -n "$OUTPUT_JSON" ]] && printf "${RESET}  JSON out : %s${RESET}\n" "$OUTPUT_JSON" >/dev/tty
    printf '\n' >/dev/tty

    if ! yes_no "Start scan?" "true"; then
        printf '\n  Scan cancelled.\n' >/dev/tty
        exit 0
    fi

    active_scanners=()
    for lbl in "${chosen_scanner_labels[@]}"; do
        for s in "${resolved_scanners[@]}"; do
            [[ "$(basename "$s")" == "$lbl" ]] && active_scanners+=("$s") && break
        done
    done
    active_mounts=("${chosen_mounts[@]}")
    suppressed_scanners_list=" ${suppressed_scanner_labels[*]} "

else
    suppressed_scanners_list=""
    # ── Non-interactive: apply CLI options ─────────────────────────────────
    active_scanners=()
    if [[ -n "$OPT_SCANNERS" ]]; then
        IFS=',' read -ra req_leaves <<< "$OPT_SCANNERS"
        for leaf in "${req_leaves[@]}"; do
            leaf="${leaf// /}"
            matched=false
            for s in "${resolved_scanners[@]}"; do
                if [[ "$(basename "$s")" == "$leaf" ]]; then
                    active_scanners+=("$s")
                    matched=true
                    break
                fi
            done
            $matched || { echo "ERROR: Requested scanner not found: $leaf" >&2; exit 1; }
        done
    else
        active_scanners=("${resolved_scanners[@]}")
    fi

    if [[ -n "$OPT_MOUNTS" ]]; then
        IFS=',' read -ra active_mounts <<< "$OPT_MOUNTS"
    else
        mapfile -t active_mounts < <(get_mount_points)
    fi

    # Build suppressed-scanners lookup from --suppress-warnings flag
    if [[ -n "$OPT_SUPPRESS" ]]; then
        _suppress_arr=()
        IFS=',' read -ra _suppress_arr <<< "$OPT_SUPPRESS"
        suppressed_scanners_list=" ${_suppress_arr[*]} "
    else
        suppressed_scanners_list=""
    fi
fi

if [[ ${#active_mounts[@]} -eq 0 ]]; then
    echo "No mount points found to scan."
    exit 0
fi

# ── Header (non-interactive path) ────────────────────────────────────────────
if ! $IS_INTERACTIVE; then
    echo ""
    echo "Supply Chain Hack Scanner"
    echo "========================="
    echo "Version $_version"
    echo "© 2026 Sooke Software — Ted Neustaedter. All rights reserved."
    echo "https://sookesoft.com"
    echo ""
    printf '%b%s%b\n' "$DARK_YELLOW" "DISCLAIMER: This tool is provided as-is for informational and defensive security" "$RESET"
    printf '%b%s%b\n' "$DARK_YELLOW" "purposes only. It does not guarantee complete detection of all supply chain threats." "$RESET"
    printf '%b%s%b\n' "$DARK_YELLOW" "Detections are based on heuristic pattern matching and may produce false positives \u2014" "$RESET"
    printf '%b%s%b\n' "$DARK_YELLOW" "reported findings should not be treated as confirmed indicators of compromise without" "$RESET"
    printf '%b%s%b\n' "$DARK_YELLOW" "independent verification. Conversely, the absence of findings does not guarantee that" "$RESET"
    printf '%b%s%b\n' "$DARK_YELLOW" "a project is free from supply chain risk. Attackers may leave misleading breadcrumbs," "$RESET"
    printf '%b%s%b\n' "$DARK_YELLOW" "intentionally crafted evidence, or obfuscated indicators that circumvent these checks." "$RESET"
    printf '%b%s%b\n' "$DARK_YELLOW" "Results should be reviewed by a qualified security professional in the full context of" "$RESET"
    printf '%b%s%b\n' "$DARK_YELLOW" "your environment. Sooke Software and Ted Neustaedter accept no liability for actions" "$RESET"
    printf '%b%s%b\n' "$DARK_YELLOW" "taken or not taken based on this output." "$RESET"
    echo ""
fi

echo ""
printf "${CYAN}Starting scan — %s${RESET}\n" "$(date '+%Y-%m-%d %H:%M:%S')"
printf "${GRAY}Scanners  : %s${RESET}\n" "$(printf '%s ' "${active_scanners[@]}" | xargs -n1 basename | tr '\n' ' ')"
printf "${GRAY}Mounts    : %s${RESET}\n" "${active_mounts[*]}"
echo ""

# ── Build find exclusion arguments ────────────────────────────────────────────
find_excl_args=()
first_excl=true
for excl in "${EXCLUDED_DIR_NAMES[@]}"; do
    if $first_excl; then first_excl=false; else find_excl_args+=(-o); fi
    find_excl_args+=(-name "$excl")
done

# ── Global state ──────────────────────────────────────────────────────────────
all_findings=()
scanner_errors=()
declare -A mount_folder_counts

# ── Temp file for per-folder scanner output ───────────────────────────────────
tmpfile=$(mktemp)
trap 'rm -f "$tmpfile"' EXIT

# ── Main scan loop ────────────────────────────────────────────────────────────
for mount in "${active_mounts[@]}"; do
    mount_folder_counts["$mount"]=0
    echo "Scanning mount point: $mount ..."

    # Build find command
    find_cmd=(find "$mount" -xdev)
    if [[ ${#find_excl_args[@]} -gt 0 ]]; then
        find_cmd+=(\( "${find_excl_args[@]}" \) -prune -o)
    fi
    find_cmd+=(-type d -print0)

    while IFS= read -r -d '' folder; do
        (( mount_folder_counts["$mount"]++ )) || true
        show_progress "$folder"

        for scanner in "${active_scanners[@]}"; do
            scanner_name="$(basename "$scanner")"

            # Check whether this scanner's console output is suppressed
            _is_suppressed=false
            [[ "$suppressed_scanners_list" == *" $scanner_name "* ]] && _is_suppressed=true

            if bash "$scanner" "$folder" "$VERBOSITY" >"$tmpfile" 2>/dev/null; then
                [[ -s "$tmpfile" ]] || continue

                # Get unique file paths reported in this scanner pass
                mapfile -t file_paths < <(jq -r '.path' "$tmpfile" 2>/dev/null | sort -u)

                for fpath in "${file_paths[@]}"; do
                    high_count=$(jq -r --arg p "$fpath" \
                        'select(.path==$p and .severity=="HIGH") | .severity' \
                        "$tmpfile" 2>/dev/null | wc -l | tr -d ' ')
                    medium_count=$(jq -r --arg p "$fpath" \
                        'select(.path==$p and .severity=="Medium") | .severity' \
                        "$tmpfile" 2>/dev/null | wc -l | tr -d ' ')

                    clear_progress

                    if ! $_is_suppressed; then
                        if (( high_count > 0 )); then
                            printf "  ${YELLOW}Scanning: %s  ⚠${RESET}\n" "$fpath"
                        elif (( medium_count > 0 )); then
                            printf "  ${YELLOW}Scanning: %s  ⚠${RESET}\n" "$fpath"
                        else
                            printf "  ${GREEN}Scanning: %s  ✓${RESET}\n" "$fpath"
                        fi

                        # Print finding details for this file
                        while IFS= read -r finding_json; do
                            [[ -z "$finding_json" ]] && continue
                            IFS=$'\t' read -r sev indicator evidence < <(jq -r \
                                '[.severity,.indicator,.evidence] | @tsv' \
                                <<< "$finding_json" 2>/dev/null)
                            case "$sev" in
                                HIGH)
                                    printf "    ${YELLOW}⚠ [%s] %s${RESET}\n" "$scanner_name" "$indicator"
                                    printf "      ${YELLOW}%s${RESET}\n" "$evidence"
                                    ;;
                                Medium)
                                    printf "    ${YELLOW}⚠ [%s] %s${RESET}\n" "$scanner_name" "$indicator"
                                    printf "      ${YELLOW}%s${RESET}\n" "$evidence"
                                    ;;
                            esac
                        done < <(jq -c --arg p "$fpath" 'select(.path==$p)' "$tmpfile" 2>/dev/null)
                    fi

                    # Augment every finding with mount + scanner and store (regardless of suppression)
                    while IFS= read -r finding_json; do
                        [[ -z "$finding_json" ]] && continue
                        augmented=$(jq -cn \
                            --argjson f "$finding_json" \
                            --arg mount "$mount" \
                            --arg scanner "$scanner_name" \
                            '$f + {mount:$mount,scanner:$scanner}' 2>/dev/null)
                        all_findings+=("$augmented")
                    done < <(jq -c --arg p "$fpath" 'select(.path==$p)' "$tmpfile" 2>/dev/null)
                done
            else
                clear_progress
                scanner_errors+=("$mount|$folder|$scanner_name|Scanner returned non-zero exit")
                printf "  ${GRAY}Scanner error in %s${RESET}\n" "$folder"
            fi
        done
    done < <("${find_cmd[@]}" 2>/dev/null)

    clear_progress
done

# ── Findings table ────────────────────────────────────────────────────────────
echo ""
printf "${CYAN}Findings${RESET}\n"
printf "${CYAN}========${RESET}\n"
echo ""

if [[ ${#all_findings[@]} -eq 0 ]]; then
    printf "${GREEN}No findings reported by any scanner.${RESET}\n"
else
    # Sort: HIGH=0, Medium=1, Info=2 — then by mount, scanner, package, path
    declare -a sorted_findings=()
    while IFS= read -r line; do
        sorted_findings+=("$line")
    done < <(
        for f in "${all_findings[@]}"; do
            sev=$(jq -r '.severity' <<< "$f" 2>/dev/null)
            case "$sev" in HIGH) rank=0 ;; Medium) rank=1 ;; Info) rank=2 ;; *) rank=3 ;; esac
            printf '%d\t%s\n' "$rank" "$f"
        done | sort -k1,1n | cut -f2-
    )

    printf "%-8s  %-18s  %-28s  %-18s  %-10s  %-45s  %s\n" \
        "Severity" "Mount" "Scanner" "Package" "Version" "Indicator" "Path"
    printf '%0.s─' {1..170}; echo

    for finding in "${sorted_findings[@]}"; do
        read -r sev mount_val scanner pkg ver indicator fpath < <(
            jq -r '[.severity,.mount,.scanner,.packageName,.version,.indicator,.path] | @tsv' \
            <<< "$finding" 2>/dev/null)
        color="$RESET"
        case "$sev" in HIGH) color="$RED" ;; Medium) color="$YELLOW" ;; esac
        printf "${color}%-8s  %-18s  %-28s  %-18s  %-10s  %-45s  %s${RESET}\n" \
            "$sev" "${mount_val:0:18}" "${scanner:0:28}" "${pkg:0:18}" \
            "${ver:0:10}" "${indicator:0:45}" "$fpath"
    done
fi

# ── Per-mount summary ─────────────────────────────────────────────────────────
echo ""
printf "${CYAN}Per-mount summary${RESET}\n"
printf "${CYAN}=================${RESET}\n"
echo ""

total_folders=0
for count in "${mount_folder_counts[@]}"; do
    (( total_folders += count )) || true
done
printf "${GRAY}Folders scanned: %d${RESET}\n" "$total_folders"
echo ""

printf "%-32s  %10s  %6s  %8s  %6s  %7s  %s\n" \
    "Mount" "Folders" "HIGH" "Medium" "Info" "Total" "Status"
printf '%0.s─' {1..90}; echo

for mount in "${active_mounts[@]}"; do
    folders="${mount_folder_counts[$mount]:-0}"
    if [[ ${#all_findings[@]} -gt 0 ]]; then
        high_c=$(  printf '%s\n' "${all_findings[@]}" | jq -rs --arg m "$mount" '[.[] | select(.mount==$m and .severity=="HIGH")]   | length' 2>/dev/null || echo 0)
        medium_c=$(printf '%s\n' "${all_findings[@]}" | jq -rs --arg m "$mount" '[.[] | select(.mount==$m and .severity=="Medium")] | length' 2>/dev/null || echo 0)
        info_c=$(  printf '%s\n' "${all_findings[@]}" | jq -rs --arg m "$mount" '[.[] | select(.mount==$m and .severity=="Info")]   | length' 2>/dev/null || echo 0)
    else
        high_c=0; medium_c=0; info_c=0
    fi
    total_c=$(( high_c + medium_c + info_c ))

    if (( high_c > 0 )); then   status="ATTENTION NEEDED"; color="$RED"
    elif (( medium_c > 0 )); then status="REVIEW";          color="$YELLOW"
    else                          status="OK";              color="$GREEN"
    fi

    printf "${color}%-32s  %10s  %6s  %8s  %6s  %7s  %s${RESET}\n" \
        "${mount:0:32}" "$folders" "$high_c" "$medium_c" "$info_c" "$total_c" "$status"
done

# ── Scanner errors ────────────────────────────────────────────────────────────
if [[ ${#scanner_errors[@]} -gt 0 ]]; then
    echo ""
    printf "${YELLOW}Scanner errors${RESET}\n"
    printf "${YELLOW}==============${RESET}\n"
    printf "%-20s  %-50s  %-30s  %s\n" "Mount" "Folder" "Scanner" "Error"
    for err in "${scanner_errors[@]}"; do
        IFS='|' read -r emount efolder escanner eerr <<< "$err"
        printf "%-20s  %-50s  %-30s  %s\n" "$emount" "${efolder:0:50}" "$escanner" "$eerr"
    done
fi

# ── JSON output ───────────────────────────────────────────────────────────────
if [[ -n "$OUTPUT_JSON" ]]; then
    scan_time=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # Build findings JSON array
    findings_json="[]"
    for f in "${all_findings[@]}"; do
        findings_json=$(jq -cn --argjson arr "$findings_json" --argjson item "$f" '$arr + [$item]' 2>/dev/null)
    done

    # Build per-mount summary JSON array
    summary_json="[]"
    for mount in "${active_mounts[@]}"; do
        folders="${mount_folder_counts[$mount]:-0}"
        if [[ ${#all_findings[@]} -gt 0 ]]; then
            high_c=$(  printf '%s\n' "${all_findings[@]}" | jq -rs --arg m "$mount" '[.[] | select(.mount==$m and .severity=="HIGH")]   | length' 2>/dev/null || echo 0)
            medium_c=$(printf '%s\n' "${all_findings[@]}" | jq -rs --arg m "$mount" '[.[] | select(.mount==$m and .severity=="Medium")] | length' 2>/dev/null || echo 0)
            info_c=$(  printf '%s\n' "${all_findings[@]}" | jq -rs --arg m "$mount" '[.[] | select(.mount==$m and .severity=="Info")]   | length' 2>/dev/null || echo 0)
        else
            high_c=0; medium_c=0; info_c=0
        fi
        total_c=$(( high_c + medium_c + info_c ))
        if (( high_c > 0 )); then status="ATTENTION NEEDED"
        elif (( medium_c > 0 )); then status="REVIEW"
        else status="OK"; fi

        entry=$(jq -cn \
            --arg  mount   "$mount" \
            --argjson folders "$folders" \
            --argjson high    "$high_c" \
            --argjson medium  "$medium_c" \
            --argjson info    "$info_c" \
            --argjson total   "$total_c" \
            --arg  status  "$status" \
            '{mount:$mount,folders:$folders,high:$high,medium:$medium,info:$info,total:$total,status:$status}')
        summary_json=$(jq -cn --argjson arr "$summary_json" --argjson item "$entry" '$arr + [$item]')
    done

    # Build errors JSON array
    errors_json="[]"
    for err in "${scanner_errors[@]}"; do
        IFS='|' read -r emount efolder escanner eerr <<< "$err"
        entry=$(jq -cn \
            --arg mount   "$emount" \
            --arg folder  "$efolder" \
            --arg scanner "$escanner" \
            --arg error   "$eerr" \
            '{mount:$mount,folder:$folder,scanner:$scanner,error:$error}')
        errors_json=$(jq -cn --argjson arr "$errors_json" --argjson item "$entry" '$arr + [$item]')
    done

    _scanner_names=$(printf '%s\n' "${active_scanners[@]}" | xargs -I{} basename {} | paste -sd ',' -)
    _mounts_str=$(printf '%s ' "${active_mounts[@]}" | sed 's/ $//')
    _suppress_str=$(echo "$suppressed_scanners_list" | xargs | tr ' ' ',')

    jq -cn \
        --arg  scanTime    "$scan_time" \
        --arg  version     "$_version" \
        --arg  scanners    "$_scanner_names" \
        --arg  mounts      "$_mounts_str" \
        --arg  suppressed  "$_suppress_str" \
        --argjson verbosity  "$VERBOSITY" \
        --argjson findings   "$findings_json" \
        --argjson summary    "$summary_json" \
        --argjson errors     "$errors_json" \
        '{scanTimeUtc:$scanTime,version:$version,scannerScripts:($scanners|split(",")),mounts:($mounts|split(" ")),suppressedScanners:(if $suppressed=="" then [] else ($suppressed|split(",")) end),verbosityLevel:$verbosity,findings:$findings,perMountSummary:$summary,errors:$errors}' \
        > "$OUTPUT_JSON"

    echo ""
    printf "${CYAN}JSON report written to: %s${RESET}\n" "$OUTPUT_JSON"
fi
