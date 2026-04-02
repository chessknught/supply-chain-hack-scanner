#!/usr/bin/env bash
# © 2026 Sooke Software — Ted Neustaedter. All rights reserved.
#
# scan-system.sh — scans all local mount points using registered scanner scripts.
# Requires: bash 4+, jq
#
# Usage:
#   ./scan-system.sh [--include-removable] [--skip-network] [--output-json <path>]

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

while [[ $# -gt 0 ]]; do
    case "$1" in
        --include-removable) INCLUDE_REMOVABLE=true ;;
        --skip-network)      SKIP_NETWORK=true ;;
        --output-json)       OUTPUT_JSON="${2:?--output-json requires a path}"; shift ;;
        *) printf 'Unknown option: %s\n' "$1" >&2; exit 1 ;;
    esac
    shift
done

# ── Config ────────────────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCANNER_SCRIPTS=("$SCRIPT_DIR/scanners/scan-for-axios-hack.sh")
EXCLUDED_DIR_NAMES=('$Recycle.Bin' 'System Volume Information')

# ── Colors (ANSI) ─────────────────────────────────────────────────────────────
RED=$'\033[0;31m'
YELLOW=$'\033[0;33m'
GREEN=$'\033[0;32m'
CYAN=$'\033[0;36m'
GRAY=$'\033[0;90m'
DARK_YELLOW=$'\033[0;33m'
RESET=$'\033[0m'

# ── Progress overlay (writes directly to /dev/tty, does not affect stdout) ────
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

# ── Global state ──────────────────────────────────────────────────────────────
all_findings=()       # each element: compact JSON string with .mount and .scanner added
scanner_errors=()     # each element: "mount|folder|scanner_name|error_message"
declare -A mount_folder_counts

# ── Header and disclaimer ─────────────────────────────────────────────────────
VERSION_FILE="$SCRIPT_DIR/VERSION"
_version=$(tr -d '[:space:]' < "$VERSION_FILE" 2>/dev/null || echo "unknown")
echo ""
echo "Supply Chain Hack Scanner"
echo "========================="
echo "Version $_version"
echo "© 2026 Sooke Software — Ted Neustaedter. All rights reserved."
echo "https://sookesoft.com"
echo ""
printf '%bDISCLAIMER: This tool is provided as-is for informational and defensive security%b\n'       "$DARK_YELLOW" "$RESET"
printf '%bpurposes only. It does not guarantee complete detection of all supply chain threats.%b\n'   "$DARK_YELLOW" "$RESET"
printf '%bResults should be reviewed by a qualified professional. Sooke Software and Ted%b\n'         "$DARK_YELLOW" "$RESET"
printf '%bNeustaedter accept no liability for actions taken or not taken based on this output.%b\n'   "$DARK_YELLOW" "$RESET"
echo ""

# ── Validate and resolve scanner scripts ──────────────────────────────────────
resolved_scanners=()
for scanner in "${SCANNER_SCRIPTS[@]}"; do
    if [[ ! -f "$scanner" ]]; then
        echo "ERROR: Scanner script not found: $scanner" >&2
        exit 1
    fi
    [[ -x "$scanner" ]] || chmod +x "$scanner"
    resolved_scanners+=("$(cd "$(dirname "$scanner")" && pwd)/$(basename "$scanner")")
done

# ── Discover mount points ─────────────────────────────────────────────────────
mapfile -t mount_points < <(get_mount_points)
if [[ ${#mount_points[@]} -eq 0 ]]; then
    echo "No mount points found to scan."
    exit 0
fi

# ── Build find exclusion arguments ────────────────────────────────────────────
find_excl_args=()
first_excl=true
for excl in "${EXCLUDED_DIR_NAMES[@]}"; do
    if $first_excl; then first_excl=false; else find_excl_args+=(-o); fi
    find_excl_args+=(-name "$excl")
done

# ── Temp file for per-folder scanner output ───────────────────────────────────
tmpfile=$(mktemp)
trap 'rm -f "$tmpfile"' EXIT

# ── Main scan loop ────────────────────────────────────────────────────────────
for mount in "${mount_points[@]}"; do
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

        for scanner in "${resolved_scanners[@]}"; do
            scanner_name="$(basename "$scanner")"

            if bash "$scanner" "$folder" >"$tmpfile" 2>/dev/null; then
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

                    if (( high_count > 0 )); then
                        printf "  ${RED}Scanning: %s  ✗${RESET}\n" "$fpath"
                    elif (( medium_count > 0 )); then
                        printf "  ${YELLOW}Scanning: %s  ⚠${RESET}\n" "$fpath"
                    else
                        printf "  ${GREEN}Scanning: %s  ✓${RESET}\n" "$fpath"
                    fi

                    # Print finding details for this file
                    while IFS= read -r finding_json; do
                        [[ -z "$finding_json" ]] && continue
                        read -r sev indicator evidence < <(jq -r \
                            '[.severity,.indicator,.evidence] | @tsv' \
                            <<< "$finding_json" 2>/dev/null)
                        case "$sev" in
                            HIGH)
                                printf "    ${RED}⚠ %s${RESET}\n" "$indicator"
                                ;;
                            Medium)
                                printf "    ${YELLOW}⚠ %s — requires manual inspection${RESET}\n" "$indicator"
                                printf "      ${YELLOW}%s${RESET}\n" "$evidence"
                                ;;
                        esac

                        # Augment finding with mount + scanner and store
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

for mount in "${mount_points[@]}"; do
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
    for mount in "${mount_points[@]}"; do
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

    jq -cn \
        --arg  scanTime "$scan_time" \
        --argjson findings "$findings_json" \
        --argjson summary  "$summary_json" \
        --argjson errors   "$errors_json" \
        '{scanTimeUtc:$scanTime,findings:$findings,perMountSummary:$summary,errors:$errors}' \
        > "$OUTPUT_JSON"

    echo ""
    printf "${CYAN}JSON report written to: %s${RESET}\n" "$OUTPUT_JSON"
fi
