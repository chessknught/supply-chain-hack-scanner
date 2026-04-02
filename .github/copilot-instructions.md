# Copilot Instructions — Supply Chain Hack Scanner

## Version file — MANDATORY update on every change

This repository uses a single source-of-truth version file: `VERSION` (in the repo root).

**Every time you make any change to any file in this repository, you MUST update `VERSION`.**

### Format

```
YYYY.M.D-build<N>
```

- `YYYY.M.D` — today's date (no zero-padding on month or day)
- `build<N>` — integer build counter, starting at 1 on a new date; incremented by 1 for each change made on the same date

Examples:
```
2026.4.2-build1
2026.4.2-build2
2026.5.1-build1
```

### Rules

1. Read the current `VERSION` file before deciding the new version.
2. If the date portion matches today, increment the build number.
3. If the date portion is earlier than today, reset the build number to 1 and update the date.
4. Write the new version string (with a trailing newline) back to `VERSION`.
5. Never skip this step — even for whitespace-only or comment-only changes.

### Why this matters

Both `scan-system.ps1` and `scan-system.sh` read `VERSION` at startup and display it in the header.
An out-of-date version file means the running tool reports the wrong version, which undermines incident traceability.
