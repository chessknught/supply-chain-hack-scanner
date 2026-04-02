# © 2026 Sooke Software — Ted Neustaedter. All rights reserved.

[CmdletBinding()]
param(
    [switch]$IncludeRemovableDrives,

    [switch]$SkipNetworkDrives,

    [string]$OutputJson = ""
)

$ErrorActionPreference = 'Continue'

$ScannerScripts = @(
    ".\scanners\scan-for-axios-hack.ps1"
    ".\scanners\scan-for-lifecycle-script-abuse.ps1"
    # ".\scanners\scan-other-thing.ps1"
)

$ExcludedFolderNames = @(
    '$Recycle.Bin',
    'System Volume Information'
)


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
    $drives = Get-CimInstance Win32_LogicalDisk | Where-Object {
        $_.DriveType -in 2, 3, 4
    }

    if (-not $IncludeRemovableDrives) {
        $drives = $drives | Where-Object { $_.DriveType -ne 2 }
    }

    if ($SkipNetworkDrives) {
        $drives = $drives | Where-Object { $_.DriveType -ne 4 }
    }

    $drives | Sort-Object DeviceID
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

$scriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$resolvedScanners = New-Object System.Collections.Generic.List[string]
$allFindings = New-Object System.Collections.Generic.List[object]
$driverErrors = New-Object System.Collections.Generic.List[object]
$driveFolderCounts = @{}

foreach ($scanner in $ScannerScripts) {
    $scannerPath = $scanner
    if (-not [System.IO.Path]::IsPathRooted($scannerPath)) {
        $scannerPath = Join-Path $scriptRoot $scannerPath
    }

    if (-not (Test-Path -LiteralPath $scannerPath)) {
        throw "Scanner script not found: $scannerPath"
    }

    $resolvedScanners.Add((Resolve-Path -LiteralPath $scannerPath).Path)
}

$drives = Get-DriveList
if (-not $drives) {
    Write-Host "No drives found to scan." -ForegroundColor Yellow
    return
}

Write-Host ""
Write-Host "Supply Chain Hack Scanner"
Write-Host "========================="
$_versionFile = Join-Path $scriptRoot 'VERSION'
$_version = if (Test-Path -LiteralPath $_versionFile) { (Get-Content -LiteralPath $_versionFile -Raw).Trim() } else { 'unknown' }
Write-Host "Version $_version"
Write-Host "© 2026 Sooke Software — Ted Neustaedter. All rights reserved."
Write-Host "https://sookesoft.com"
Write-Host ""
Write-Host "DISCLAIMER: This tool is provided as-is for informational and defensive security" -ForegroundColor DarkYellow
Write-Host "purposes only. It does not guarantee complete detection of all supply chain threats." -ForegroundColor DarkYellow
Write-Host "Results should be reviewed by a qualified professional. Sooke Software and Ted" -ForegroundColor DarkYellow
Write-Host "Neustaedter accept no liability for actions taken or not taken based on this output." -ForegroundColor DarkYellow
Write-Host ""

if ($PSStyle -and $PSStyle.Progress) {
    $PSStyle.Progress.Style = "`e[44;1;97m"   # blue background, bold, white text (PS7+)
} else {
    $Host.PrivateData.ProgressBackgroundColor = 'DarkBlue'
    $Host.PrivateData.ProgressForegroundColor = 'Cyan'
}

foreach ($drive in $drives) {
    $driveRoot = "$($drive.DeviceID)\"
    $driveLabel = if ($drive.VolumeName) { "$($drive.DeviceID) ($($drive.VolumeName))" } else { $drive.DeviceID }

    Write-Host "Scanning drive $driveLabel ..."

    $activityId = [int]([char]$drive.DeviceID.Substring(0,1))
    $driveFolderCounts[$drive.DeviceID] = 0

    Get-AllFoldersBreadthFirst -RootPath $driveRoot | ForEach-Object {
        $folder = $_
        $driveFolderCounts[$drive.DeviceID]++

        Write-Progress -Id $activityId `
            -Activity "Scanning $driveLabel" `
            -Status $folder `
            -PercentComplete -1

        foreach ($scanner in $resolvedScanners) {
            $scannerName = Split-Path $scanner -Leaf

            try {
                $results = & $scanner -ScanPath $folder

                if ($results) {
                    # One status line per file, coloured by worst finding in that file
                    $byPath = $results | Group-Object Path
                    foreach ($group in $byPath) {
                        $highProblems   = @($group.Group | Where-Object { $_.Severity -eq 'HIGH' })
                        $mediumProblems = @($group.Group | Where-Object { $_.Severity -eq 'Medium' })
                        if ($highProblems.Count -gt 0) {
                            Write-Host "  Scanning: $($group.Name)  ✗" -ForegroundColor Red
                            foreach ($r in $highProblems) {
                                Write-Host "    ⚠ [$scannerName] $($r.Indicator)" -ForegroundColor Red
                            }
                            foreach ($r in $mediumProblems) {
                                Write-Host "    ⚠ [$scannerName] $($r.Indicator) — requires manual inspection" -ForegroundColor Yellow
                                Write-Host "      $($r.Evidence)" -ForegroundColor Yellow
                            }
                        } elseif ($mediumProblems.Count -gt 0) {
                            Write-Host "  Scanning: $($group.Name)  ⚠" -ForegroundColor Yellow
                            foreach ($r in $mediumProblems) {
                                Write-Host "    ⚠ [$scannerName] $($r.Indicator) — requires manual inspection" -ForegroundColor Yellow
                                Write-Host "      $($r.Evidence)" -ForegroundColor Yellow
                            }
                        } else {
                            Write-Host "  Scanning: $($group.Name)  ✓" -ForegroundColor Green
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

    Write-Progress -Id $activityId -Activity "Scanning $driveLabel" -Completed
}

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

$summary = foreach ($drive in ($drives | Select-Object -ExpandProperty DeviceID)) {
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
        DriverScript     = $MyInvocation.MyCommand.Path
        ScannerScripts   = @($resolvedScanners)
        Findings         = @($sortedFindings)
        PerDriveSummary  = @($summary)
        Errors           = @($driverErrors)
    }

    $payload | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $OutputJson -Encoding UTF8

    Write-Host ""
    Write-Host "JSON report written to: $OutputJson" -ForegroundColor Cyan
}