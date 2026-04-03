# © 2026 Sooke Software — Ted Neustaedter. All rights reserved.

[CmdletBinding()]
param(
    # ── Non-interactive / CI flags ──────────────────────────────────────────
    # When any of these are supplied the interactive menu is skipped entirely.

    [switch]$IncludeRemovableDrives,

    [switch]$SkipNetworkDrives,

    [string]$OutputJson = "",

    # Comma-separated leaf names of scanner scripts to run, e.g.
    #   -Scanners "scan-for-axios-hack.ps1,scan-for-typosquat-packages.ps1"
    # Omit to run all registered scanners (or to be prompted interactively).
    [string]$Scanners = "",

    # Comma-separated drive letters to limit the scan to, e.g. "C:,D:"
    # Omit to scan all available drives (or to be prompted interactively).
    [string]$Drives = "",

    # 0 = quiet (default), 1 = verbose per-scanner debug output
    [int]$VerbosityLevel = 0,

    # Comma-separated leaf names of scanners whose findings should be silenced
    # from console output (findings are still written to the JSON report).
    # e.g. -SuppressWarnings "scan-for-typosquat-packages.ps1"
    [string]$SuppressWarnings = "",

    # Pass -NonInteractive to suppress the menu and use defaults / flags as-is.
    [switch]$NonInteractive
)

$ErrorActionPreference = 'Continue'

# ── Scanner registry ──────────────────────────────────────────────────────────
# Add new scanner filenames here as new scanner modules are created.
$ScannerScripts = @(
    ".\scanners\scan-for-axios-hack.ps1"
    ".\scanners\scan-for-lifecycle-script-abuse.ps1"
    ".\scanners\scan-for-suspicious-domains.ps1"
    ".\scanners\scan-for-typosquat-packages.ps1"
    ".\scanners\scan-for-dependency-confusion.ps1"
    # ".\scanners\scan-other-thing.ps1"
)

$ExcludedFolderNames = @(
    '$Recycle.Bin',
    'System Volume Information'
)

# ── Interactive menu helpers ──────────────────────────────────────────────────

function Show-Header {
    param([string]$Version)
    Clear-Host
    Write-Host ""
    Write-Host "  Supply Chain Hack Scanner  v$Version" -ForegroundColor Cyan
    Write-Host "  ══════════════════════════════════════" -ForegroundColor DarkCyan
    Write-Host "  © 2026 Sooke Software — Ted Neustaedter. All rights reserved." -ForegroundColor DarkGray
    Write-Host "  https://sookesoft.com" -ForegroundColor DarkGray
    Write-Host ""
}

function Invoke-ChecklistMenu {
    param(
        [string]$Title,
        [string[]]$Items,
        [bool[]]$Defaults
    )

    if ($Items.Count -eq 0) {
        return @()
    }

    $selected = New-Object 'bool[]' $Items.Count
    for ($i = 0; $i -lt $Items.Count; $i++) {
        $selected[$i] = [bool]$Defaults[$i]
    }
    $cursorIndex = 0

    while ($true) {
        Clear-Host
        Write-Host ""
        Write-Host "  $Title" -ForegroundColor Cyan
        Write-Host "  $('─' * ($Title.Length))" -ForegroundColor DarkCyan
        Write-Host ""
        Write-Host "  Use Up/Down to move, Space to toggle, A = all, N = none, Enter = confirm." -ForegroundColor DarkYellow
        Write-Host ""

        for ($i = 0; $i -lt $Items.Count; $i++) {
            $box = if ($selected[$i]) { '[x]' } else { '[ ]' }
            $pointer = if ($i -eq $cursorIndex) { '>' } else { ' ' }
            $color = if ($i -eq $cursorIndex) {
                'Cyan'
            } elseif ($selected[$i]) {
                'White'
            } else {
                'DarkGray'
            }
            Write-Host ("  $pointer $box {0}" -f $Items[$i]) -ForegroundColor $color
        }

        Write-Host ""
        $key = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')

        switch ($key.VirtualKeyCode) {
            38 {
                if ($cursorIndex -gt 0) { $cursorIndex-- } else { $cursorIndex = $Items.Count - 1 }
            }
            40 {
                if ($cursorIndex -lt ($Items.Count - 1)) { $cursorIndex++ } else { $cursorIndex = 0 }
            }
            32 {
                $selected[$cursorIndex] = -not $selected[$cursorIndex]
            }
            13 {
                return @(for ($j = 0; $j -lt $Items.Count; $j++) {
                    if ($selected[$j]) { $Items[$j] }
                })
            }
            default {
                switch ($key.Character) {
                    'a' { for ($i = 0; $i -lt $selected.Count; $i++) { $selected[$i] = $true } }
                    'A' { for ($i = 0; $i -lt $selected.Count; $i++) { $selected[$i] = $true } }
                    'n' { for ($i = 0; $i -lt $selected.Count; $i++) { $selected[$i] = $false } }
                    'N' { for ($i = 0; $i -lt $selected.Count; $i++) { $selected[$i] = $false } }
                }
            }
        }
    }

    for ($i = 0; $i -lt $Items.Count; $i++) {
        if ($selected[$i]) { $Items[$i] }
    }
}

# Present a Y/N prompt; returns $true for Yes.
function Invoke-YesNo {
    param([string]$Prompt, [bool]$Default = $false)
    $hint = if ($Default) { '[Y/n]' } else { '[y/N]' }
    Write-Host "  $Prompt $hint : " -ForegroundColor DarkYellow -NoNewline
    $r = (Read-Host).Trim()
    if ($r -eq '') { return $Default }
    return $r -match '^[Yy]'
}

# Prompt for a string; returns the typed value or $Default if empty.
function Invoke-StringPrompt {
    param([string]$Prompt, [string]$Default = '')
    $hint = if ($Default) { "(default: $Default)" } else { '(leave blank to skip)' }
    Write-Host "  $Prompt $hint : " -ForegroundColor DarkYellow -NoNewline
    $r = (Read-Host).Trim()
    if ($r -eq '') { return $Default }
    return $r
}

# Single-choice menu from a numbered list; returns the chosen item.
function Invoke-SingleChoiceMenu {
    param(
        [string]$Title,
        [string[]]$Items,
        [int]$DefaultIndex = 0
    )

    if ($Items.Count -eq 0) {
        return $null
    }

    $cursorIndex = if ($DefaultIndex -ge 0 -and $DefaultIndex -lt $Items.Count) { $DefaultIndex } else { 0 }

    while ($true) {
        Clear-Host
        Write-Host ""
        Write-Host "  $Title" -ForegroundColor Cyan
        Write-Host "  $('─' * ($Title.Length))" -ForegroundColor DarkCyan
        Write-Host ""
        Write-Host "  Use Up/Down to move, Enter to confirm." -ForegroundColor DarkYellow
        Write-Host ""
        for ($i = 0; $i -lt $Items.Count; $i++) {
            $marker = if ($i -eq $cursorIndex) { '>' } else { ' ' }
            $color  = if ($i -eq $cursorIndex) { 'Cyan' } else { 'DarkGray' }
            Write-Host ("  $marker {0}" -f $Items[$i]) -ForegroundColor $color
        }
        Write-Host ""

        $key = $Host.UI.RawUI.ReadKey('NoEcho,IncludeKeyDown')
        switch ($key.VirtualKeyCode) {
            38 {
                if ($cursorIndex -gt 0) { $cursorIndex-- } else { $cursorIndex = $Items.Count - 1 }
            }
            40 {
                if ($cursorIndex -lt ($Items.Count - 1)) { $cursorIndex++ } else { $cursorIndex = 0 }
            }
            13 {
                return $Items[$cursorIndex]
            }
        }
    }
}


function Get-SeveritySortValue {
    param([string]$Severity)

    switch ($Severity) {
        'HIGH'   { 0 }
        'Medium' { 1 }
        'Info'   { 2 }
        default  { 3 }
    }
}

function Get-DriveList {
    $driveList = Get-CimInstance Win32_LogicalDisk | Where-Object {
        $_.DriveType -in 2, 3, 4
    }

    if (-not $IncludeRemovableDrives) {
        $driveList = $driveList | Where-Object { $_.DriveType -ne 2 }
    }

    if ($SkipNetworkDrives) {
        $driveList = $driveList | Where-Object { $_.DriveType -ne 4 }
    }

    $driveList | Sort-Object DeviceID
}

function Get-AllFoldersBreadthFirst {
    param(
        [string]$RootPath
    )

    $queue = New-Object System.Collections.Queue
    $queue.Enqueue($RootPath)

    while ($queue.Count -gt 0) {
        $current = [string]$queue.Dequeue()
        $current

        try {
            $children = Get-ChildItem -LiteralPath $current -Directory -Force -ErrorAction Stop
            foreach ($child in $children) {
                if ($ExcludedFolderNames -contains $child.Name) {
                    continue
                }
                $queue.Enqueue($child.FullName)
            }
        }
        catch {
        }
    }
}

function Show-ProgressLine {
    param([string]$Text)

    try {
        $width = [Math]::Max(20, $Host.UI.RawUI.WindowSize.Width)
    }
    catch {
        $width = 80
    }

    $contentWidth = [Math]::Max(1, $width - 1)
    $displayText = if ($Text.Length -gt $contentWidth) {
        $Text.Substring(0, $contentWidth)
    }
    else {
        $Text.PadRight($contentWidth)
    }

    Write-Host ("`r$displayText") -NoNewline -BackgroundColor DarkBlue -ForegroundColor White
}

function Clear-ProgressLine {
    try {
        $width = [Math]::Max(20, $Host.UI.RawUI.WindowSize.Width)
    }
    catch {
        $width = 80
    }

    $blank = ' ' * [Math]::Max(1, $width - 1)
    Write-Host ("`r$blank`r") -NoNewline
}

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# Read version
$_versionFile = Join-Path $scriptRoot 'VERSION'
$_version = if (Test-Path -LiteralPath $_versionFile) { (Get-Content -LiteralPath $_versionFile -Raw).Trim() } else { 'unknown' }

# Detect whether stdin is a terminal (interactive session).
$_isInteractive = [Environment]::UserInteractive -and
                  -not $NonInteractive -and
                  $Scanners         -eq '' -and
                  $Drives           -eq '' -and
                  -not $IncludeRemovableDrives -and
                  -not $SkipNetworkDrives -and
                  $OutputJson       -eq '' -and
                  $VerbosityLevel   -eq 0 -and
                  $SuppressWarnings -eq ''

# ── Resolve the full list of available scanners ───────────────────────────────
$allAvailableScanners = [System.Collections.Generic.List[string]]::new()
foreach ($s in $ScannerScripts) {
    $p = if ([System.IO.Path]::IsPathRooted($s)) { $s } else { Join-Path $scriptRoot $s }
    if (Test-Path -LiteralPath $p) { $allAvailableScanners.Add((Resolve-Path -LiteralPath $p).Path) }
}

$targetDrives = @()

# ── Interactive menu ──────────────────────────────────────────────────────────
if ($_isInteractive) {
    Show-Header $_version

    Write-Host "  DISCLAIMER: This tool is provided as-is for informational and defensive security" -ForegroundColor DarkYellow
    Write-Host "  purposes only. It does not guarantee complete detection of all supply chain threats." -ForegroundColor DarkYellow
    Write-Host "  Detections are based on heuristic pattern matching and may produce false positives —" -ForegroundColor DarkYellow
    Write-Host "  reported findings should not be treated as confirmed indicators of compromise without" -ForegroundColor DarkYellow
    Write-Host "  independent verification. Conversely, the absence of findings does not guarantee that" -ForegroundColor DarkYellow
    Write-Host "  a project is free from supply chain risk. Attackers may leave misleading breadcrumbs," -ForegroundColor DarkYellow
    Write-Host "  intentionally crafted evidence, or obfuscated indicators that circumvent these checks." -ForegroundColor DarkYellow
    Write-Host "  Results should be reviewed by a qualified security professional in the full context of" -ForegroundColor DarkYellow
    Write-Host "  your environment. Sooke Software and Ted Neustaedter accept no liability for actions" -ForegroundColor DarkYellow
    Write-Host "  taken or not taken based on this output." -ForegroundColor DarkYellow
    Write-Host ""

    # — Scanner selection ——————————————————————————————————————————————————————
    $scannerLabels  = @($allAvailableScanners | ForEach-Object { Split-Path $_ -Leaf })
    $scannerDefaults = @($scannerLabels | ForEach-Object { $true })

    $chosenLabels = @(Invoke-ChecklistMenu `
        -Title    'Select scanners to run' `
        -Items    $scannerLabels `
        -Defaults $scannerDefaults)

    if ($chosenLabels.Count -eq 0) {
        Write-Host ""
        Write-Host "  No scanners selected — nothing to do." -ForegroundColor Yellow
        return
    }

    # — Drive selection ————————————————————————————————————————————————————————
    $allDrives = @(Get-CimInstance Win32_LogicalDisk | Where-Object { $_.DriveType -in 2, 3, 4 } | Sort-Object DeviceID)
    $driveLabels   = @($allDrives | ForEach-Object {
        $label = if ($_.VolumeName) { "$($_.DeviceID) ($($_.VolumeName))" } else { $_.DeviceID }
        $typeStr = switch ($_.DriveType) { 3 { 'Fixed' } 4 { 'Network' } 2 { 'Removable' } default { 'Other' } }
        "$label  [$typeStr]"
    })
    $driveDefaults = @($allDrives | ForEach-Object { $_.DriveType -eq 3 })   # default: fixed drives only

    $chosenDriveLabels = @(Invoke-ChecklistMenu `
        -Title    'Select drives to scan' `
        -Items    $driveLabels `
        -Defaults $driveDefaults)

    if ($chosenDriveLabels.Count -eq 0) {
        Write-Host ""
        Write-Host "  No drives selected — nothing to do." -ForegroundColor Yellow
        return
    }

    # Map chosen drive labels back to drive objects and DeviceID strings
    $chosenDrives   = [System.Collections.Generic.List[object]]::new()
    $chosenDriveIds = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $driveLabels.Count; $i++) {
        if ($chosenDriveLabels -contains $driveLabels[$i]) {
            $chosenDrives.Add($allDrives[$i])
            $chosenDriveIds.Add($allDrives[$i].DeviceID)
        }
    }

    # — Options ————————————————————————————————————————————————————————————————
    Show-Header $_version
    Write-Host "  Scan options" -ForegroundColor Cyan
    Write-Host "  ────────────" -ForegroundColor DarkCyan
    Write-Host ""

    $verbChoice = Invoke-SingleChoiceMenu `
        -Title        'Verbosity level' `
        -Items        @('0 — Quiet (findings only)', '1 — Verbose (per-scanner debug output)') `
        -DefaultIndex 0
    $VerbosityLevel = if ($verbChoice -like '1*') { 1 } else { 0 }

    $OutputJson = Invoke-StringPrompt -Prompt 'Save JSON report to file path' -Default ''

    # — Warning suppression ———————————————————————————————————————————————————
    $suppressDefaults = @($chosenLabels | ForEach-Object { $false })
    $suppressedLabels = @(Invoke-ChecklistMenu `
        -Title    'Suppress console warnings for which scanners? (findings still saved to JSON)' `
        -Items    $chosenLabels `
        -Defaults $suppressDefaults)

    # — Confirmation ———————————————————————————————————————————————————————————
    Show-Header $_version
    Write-Host "  Ready to scan" -ForegroundColor Cyan
    Write-Host "  ─────────────" -ForegroundColor DarkCyan
    Write-Host ""

    Write-Host "  Drives" -ForegroundColor White
    Write-Host "  ------" -ForegroundColor DarkGray
    foreach ($driveId in $chosenDriveIds) {
        Write-Host "   - $driveId" -ForegroundColor White
    }
    Write-Host ""

    Write-Host "  Scanners" -ForegroundColor White
    Write-Host "  --------" -ForegroundColor DarkGray
    foreach ($label in $chosenLabels) {
        $suffix = if ($suppressedLabels -contains $label) { ' (no warnings)' } else { '' }
        Write-Host "   - $label$suffix" -ForegroundColor White
    }
    Write-Host ""

    $verbosityLabel = if ($VerbosityLevel -eq 1) {
        'Verbose (per-scanner debug output)'
    } else {
        'Quiet (findings only)'
    }
    Write-Host "  Verbosity: $verbosityLabel" -ForegroundColor White
    if ($OutputJson) { Write-Host "  JSON out : $OutputJson" -ForegroundColor White }
    Write-Host ""

    if (-not (Invoke-YesNo -Prompt 'Start scan?' -Default $true)) {
        Write-Host ""
        Write-Host "  Scan cancelled." -ForegroundColor Yellow
        return
    }

    # Apply selections to the variables used by the rest of the script
    $resolvedScanners = New-Object System.Collections.Generic.List[string]
    foreach ($lbl in $chosenLabels) {
        $match = $allAvailableScanners | Where-Object { (Split-Path $_ -Leaf) -eq $lbl }
        if ($match) { $resolvedScanners.Add($match) }
    }

    $script:_suppressedScanners = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]$suppressedLabels, [System.StringComparer]::OrdinalIgnoreCase)

    $targetDrives = @($chosenDrives.ToArray())
}
else {
    # ── Non-interactive: respect CLI flags ────────────────────────────────────
    # Validate that at least one scanner exists
    if ($allAvailableScanners.Count -eq 0) {
        throw "No scanner scripts found. Check the ScannerScripts array."
    }

    $resolvedScanners = New-Object System.Collections.Generic.List[string]

    if ($Scanners -ne '') {
        $requestedLeaves = $Scanners -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        foreach ($leaf in $requestedLeaves) {
            $match = $allAvailableScanners | Where-Object { (Split-Path $_ -Leaf) -eq $leaf }
            if (-not $match) { throw "Requested scanner not found: $leaf" }
            $resolvedScanners.Add($match)
        }
    } else {
        $allAvailableScanners | ForEach-Object { $resolvedScanners.Add($_) }
    }

    $chosenDriveIds = @()
    if ($Drives -ne '') {
        $chosenDriveIds = @($Drives -split ',' | ForEach-Object { $_.Trim().TrimEnd('\') } | Where-Object { $_ })
    }

    $script:_suppressedScanners = [System.Collections.Generic.HashSet[string]]::new(
        [string[]]($SuppressWarnings -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }),
        [System.StringComparer]::OrdinalIgnoreCase)

    $targetDrives = Get-DriveList
    if ($chosenDriveIds -and @($chosenDriveIds).Count -gt 0) {
        $chosenSet = [System.Collections.Generic.HashSet[string]]::new(
            [string[]]($chosenDriveIds | ForEach-Object { $_.TrimEnd('\') }),
            [System.StringComparer]::OrdinalIgnoreCase)
        $targetDrives = @($targetDrives | Where-Object { $_ -and $_.DeviceID -and $chosenSet.Contains($_.DeviceID.TrimEnd('\')) })
    }
}

# ── Progress-bar style ────────────────────────────────────────────────────────
if ($PSStyle -and $PSStyle.Progress) {
    $PSStyle.Progress.Style = "`e[44;1;97m"
} else {
    try { $Host.PrivateData.ProgressBackgroundColor = 'DarkBlue' }  catch {}
    try { $Host.PrivateData.ProgressForegroundColor = 'Cyan'     }  catch {}
}

if (-not $targetDrives -or @($targetDrives).Count -eq 0) {
    Write-Host "No drives found to scan." -ForegroundColor Yellow
    return
}

$targetDrives = @($targetDrives | Where-Object { $_ -and $_.PSObject.Properties['DeviceID'] -and -not [string]::IsNullOrWhiteSpace([string]$_.DeviceID) })

if (-not $targetDrives -or @($targetDrives).Count -eq 0) {
    Write-Host "No valid drives found to scan." -ForegroundColor Yellow
    return
}

# ── Header (non-interactive path) ────────────────────────────────────────────
if (-not $_isInteractive) {
    Write-Host ""
    Write-Host "Supply Chain Hack Scanner"
    Write-Host "========================="
    Write-Host "Version $_version"
    Write-Host "© 2026 Sooke Software — Ted Neustaedter. All rights reserved."
    Write-Host "https://sookesoft.com"
    Write-Host ""
    Write-Host "DISCLAIMER: This tool is provided as-is for informational and defensive security" -ForegroundColor DarkYellow
    Write-Host "purposes only. It does not guarantee complete detection of all supply chain threats." -ForegroundColor DarkYellow
    Write-Host "Detections are based on heuristic pattern matching and may produce false positives —" -ForegroundColor DarkYellow
    Write-Host "reported findings should not be treated as confirmed indicators of compromise without" -ForegroundColor DarkYellow
    Write-Host "independent verification. Conversely, the absence of findings does not guarantee that" -ForegroundColor DarkYellow
    Write-Host "a project is free from supply chain risk. Attackers may leave misleading breadcrumbs," -ForegroundColor DarkYellow
    Write-Host "intentionally crafted evidence, or obfuscated indicators that circumvent these checks." -ForegroundColor DarkYellow
    Write-Host "Results should be reviewed by a qualified security professional in the full context of" -ForegroundColor DarkYellow
    Write-Host "your environment. Sooke Software and Ted Neustaedter accept no liability for actions" -ForegroundColor DarkYellow
    Write-Host "taken or not taken based on this output." -ForegroundColor DarkYellow
    Write-Host ""
}

Write-Host ""
Write-Host "Starting scan — $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "Scanners  : $(($resolvedScanners | ForEach-Object { Split-Path $_ -Leaf }) -join ', ')" -ForegroundColor DarkGray
Write-Host "Drives    : $((@($targetDrives | ForEach-Object { $_.DeviceID })) -join ', ')" -ForegroundColor DarkGray
Write-Host ""

$allFindings    = New-Object System.Collections.Generic.List[object]
$driverErrors   = New-Object System.Collections.Generic.List[object]
$driveFolderCounts = @{}

# Pre-compute which scanners accept -VerbosityLevel (avoids a parameter-binding
# error at runtime if a scanner was written before the parameter was standardised).
$_scannerVerbositySupport = @{}
foreach ($_s in $resolvedScanners) {
    try {
        $_scannerVerbositySupport[$_s] = (Get-Command $_s -ErrorAction Stop).Parameters.ContainsKey('VerbosityLevel')
    } catch {
        $_scannerVerbositySupport[$_s] = $false
    }
}

foreach ($drive in $targetDrives) {
    $driveRoot = "$($drive.DeviceID)\"
    $driveFolderCounts[$drive.DeviceID] = 0

    Get-AllFoldersBreadthFirst -RootPath $driveRoot | ForEach-Object {
        $folder = $_
        $driveFolderCounts[$drive.DeviceID]++

        Show-ProgressLine -Text $folder

        foreach ($scanner in $resolvedScanners) {
            $scannerName = Split-Path $scanner -Leaf
            $isSuppressed = $script:_suppressedScanners.Contains($scannerName)

            try {
                $scanArgs = @{ ScanPath = $folder }
                if ($_scannerVerbositySupport[$scanner]) { $scanArgs['VerbosityLevel'] = $VerbosityLevel }
                $results = & $scanner @scanArgs

                if ($results) {
                    Clear-ProgressLine

                    # One status line per file, coloured by worst finding in that file
                    $byPath = $results | Group-Object Path
                    foreach ($group in $byPath) {
                        $highProblems   = @($group.Group | Where-Object { $_.Severity -eq 'HIGH' })
                        $mediumProblems = @($group.Group | Where-Object { $_.Severity -eq 'Medium' })
                        if (-not $isSuppressed) {
                            if ($highProblems.Count -gt 0) {
                                Write-Host "  Scanning: $($group.Name)  ⚠" -ForegroundColor Yellow
                                foreach ($r in $highProblems) {
                                    Write-Host "    ⚠ [$scannerName] $($r.Indicator)" -ForegroundColor Yellow
                                    Write-Host "      $($r.Evidence)" -ForegroundColor Yellow
                                }
                                foreach ($r in $mediumProblems) {
                                    Write-Host "    ⚠ [$scannerName] $($r.Indicator)" -ForegroundColor Yellow
                                    Write-Host "      $($r.Evidence)" -ForegroundColor Yellow
                                }
                            } elseif ($mediumProblems.Count -gt 0) {
                                Write-Host "  Scanning: $($group.Name)  ⚠" -ForegroundColor Yellow
                                foreach ($r in $mediumProblems) {
                                    Write-Host "    ⚠ [$scannerName] $($r.Indicator)" -ForegroundColor Yellow
                                    Write-Host "      $($r.Evidence)" -ForegroundColor Yellow
                                }
                            } else {
                                Write-Host "  Scanning: $($group.Name)  ✓" -ForegroundColor Green
                            }
                        }
                    }

                    foreach ($r in $results) {
                        if (-not $r.PSObject.Properties['Drive']) {
                            $r | Add-Member -NotePropertyName Drive -NotePropertyValue $drive.DeviceID
                        }

                        if (-not $r.PSObject.Properties['Scanner']) {
                            $r | Add-Member -NotePropertyName Scanner -NotePropertyValue $scannerName
                        }

                        $allFindings.Add($r)
                    }
                }
            }
            catch {
                Clear-ProgressLine

                $driverErrors.Add([pscustomobject]@{
                    Drive   = $drive.DeviceID
                    Folder  = $folder
                    Scanner = $scannerName
                    Error   = $_.Exception.Message
                })

                Write-Host "  Scanner error in ${folder}: $($_.Exception.Message)" -ForegroundColor DarkGray
            }
        }
    }
}

Clear-ProgressLine

$sortedFindings = $allFindings | Sort-Object `
    @{ Expression = { Get-SeveritySortValue $_.Severity } }, `
    Drive, Scanner, PackageName, Version, Path

Write-Host ""
Write-Host "Findings" -ForegroundColor Cyan
Write-Host "========" -ForegroundColor Cyan
Write-Host ""

if (-not $sortedFindings -or $sortedFindings.Count -eq 0) {
    Write-Host "No findings reported by any scanner." -ForegroundColor Green
}
else {
    $sortedFindings |
        Select-Object Drive, Scanner, Severity, Type, PackageName, Version, Indicator, Path |
        Format-Table -AutoSize
}

Write-Host ""
Write-Host "Per-drive summary" -ForegroundColor Cyan
Write-Host "=================" -ForegroundColor Cyan
Write-Host ""

$totalFolders = ($driveFolderCounts.Values | Measure-Object -Sum).Sum
Write-Host "Folders scanned: $totalFolders" -ForegroundColor Gray
Write-Host ""

$summary = foreach ($drive in ($targetDrives | Select-Object -ExpandProperty DeviceID)) {
    $driveItems = @($sortedFindings | Where-Object { $_.Drive -eq $drive })

    [pscustomobject]@{
        Drive   = $drive
        Folders = $driveFolderCounts[$drive]
        High    = @($driveItems | Where-Object { $_.Severity -eq 'HIGH' }).Count
        Medium  = @($driveItems | Where-Object { $_.Severity -eq 'Medium' }).Count
        Info    = @($driveItems | Where-Object { $_.Severity -eq 'Info' }).Count
        Total   = $driveItems.Count
        Status  = if (@($driveItems | Where-Object { $_.Severity -eq 'HIGH' }).Count -gt 0) {
            'ATTENTION NEEDED'
        }
        elseif (@($driveItems | Where-Object { $_.Severity -eq 'Medium' }).Count -gt 0) {
            'REVIEW'
        }
        else {
            'OK'
        }
    }
}

$summary | Format-Table -AutoSize

if ($driverErrors.Count -gt 0) {
    Write-Host ""
    Write-Host "Driver/scanner errors" -ForegroundColor Yellow
    Write-Host "=====================" -ForegroundColor Yellow
    $driverErrors | Format-Table -AutoSize
}

if ($OutputJson) {
    $payload = [pscustomobject]@{
        ScanTimeUtc      = (Get-Date).ToUniversalTime().ToString("o")
        Version             = $_version
        DriverScript        = $MyInvocation.MyCommand.Path
        ScannerScripts      = @($resolvedScanners | ForEach-Object { Split-Path $_ -Leaf })
        SuppressedScanners  = @($script:_suppressedScanners)
        Drives              = @($targetDrives | ForEach-Object { $_.DeviceID })
        VerbosityLevel      = $VerbosityLevel
        Findings            = @($sortedFindings)
        PerDriveSummary  = @($summary)
        Errors           = @($driverErrors)
    }

    $payload | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $OutputJson -Encoding UTF8

    Write-Host ""
    Write-Host "JSON report written to: $OutputJson" -ForegroundColor Cyan
}