# Copilot Instructions — Supply Chain Hack Scanner

## Version file — MANDATORY update on every change

This repository uses a single source-of-truth version file: `VERSION` (in the repo root).

**Every time you make any change to any file in this repository, you MUST update `VERSION`.**

### Format

```
YYYY.M.D-build<N>
```

- `YYYY.M.D` — today's date (no zero-padding on month or day)
- `build<N>` — integer build counter that is always incremented from the current `VERSION`, regardless of date changes

Examples:
```
2026.4.2-build1
2026.4.2-build2
2026.5.1-build3
```

### Rules

1. Read the current `VERSION` file before deciding the new version.
2. Set the date portion to today.
3. Increment the existing build number by 1, even if the date portion changes.
4. Write the new version string (with a trailing newline) back to `VERSION`.
5. Never skip this step — even for whitespace-only or comment-only changes.

### Why this matters

Both `scan-system.ps1` and `scan-system.sh` read `VERSION` at startup and display it in the header.
An out-of-date version file means the running tool reports the wrong version, which undermines incident traceability.

---

## CRITICAL — AV false-positive prevention for scanner pattern strings

This repository's scanner scripts contain regex patterns that match malware indicators (dangerous binaries, obfuscation functions, exfiltration URLs, etc.). Those same literal strings will trigger antivirus / EDR static analysis on the scanner files themselves if they appear verbatim in source.

**Rule: never write a detectable malware indicator string as a single unbroken literal in any `.ps1` or `.sh` scanner file.**

### PowerShell (`.ps1`)

Split the string with `+` concatenation so the dangerous substring does not exist as a contiguous literal:

```powershell
# BAD — AV will flag this file
@{ Pattern = 'rundll32' }
@{ Pattern = 'FromBase64String' }
@{ Pattern = 'Invoke-WebRequest' }

# GOOD — assembled at runtime, no static signature
@{ Pattern = 'run' + 'dll32' }
@{ Pattern = 'From' + 'Base' + '64String' }
@{ Pattern = 'Invoke-Web' + 'Request' }
```

### Bash (`.sh`)

Use a variable to hold a fragment, or split across a concatenation:

```bash
# BAD
SUSPICIOUS_PATTERNS=("HIGH|rundll32|\brundll32\b")

# GOOD
_r='rundll'; SUSPICIOUS_PATTERNS=("HIGH|rundll32|\b${_r}32\b")
```

### What must always be split

Any string that matches a well-known malware technique must be split. At minimum:

- Windows LOLBins: `rundll32`, `regsvr32`, `mshta`, `cscript`, `wscript`, `bitsadmin`, `certutil`
- PowerShell attack cmdlets: `Invoke-WebRequest`, `Start-Process`, `FromBase64String`
- Code execution patterns: `eval(`, `atob(`, `child_process`, `spawn(`
- Known malicious domains or IPs from threat-intel (e.g. `sfrclak.com` → `'sfrcl' + 'ak.com'`)
- Exfiltration endpoints: Discord webhook paths, Telegram bot API paths
- Obfuscation keywords: `base64`, `FromBase64`, `powershell -enc`

### Why this matters

Windows Defender and other AV/EDR engines perform static string scanning on script files before execution. A scanner that is blocked by AV cannot protect the machine it is running on.
