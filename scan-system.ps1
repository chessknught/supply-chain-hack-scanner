[CmdletBinding()]
param(
    [ValidateSet('Quiet','Normal','Detailed','Debug')]
    [string]$VerbosityLevel = 'Detailed',

    [switch]$IncludeRemovableDrives,

    [switch]$SkipNetworkDrives,

    [string]$OutputJson = ""
)

$ErrorActionPreference = 'Continue'

$ScannerScripts = @(
    ".\scanners\scan-for-axios-hack.ps1"
    # ".\scanners\scan-other-thing.ps1"
)

$ExcludedFolderNames = @(
    '$Recycle.Bin',
    'System Volume Information'
)

function Write-Log {
    param(
        [string]$Level,
        [string]$Message
    )

    $rank = @{
        Quiet    = 0
        Normal   = 1
        Detailed = 2
        Debug    = 3
    }

    if ($rank[$Level] -le $rank[$VerbosityLevel]) {
        switch ($Level) {
            'Debug'    { Write-Host "[DEBUG] $Message" -ForegroundColor DarkGray }
            'Detailed' { Write-Host "[DETAIL] $Message" -ForegroundColor Gray }
            default    { Write-Host $Message }
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

Write-Log -Level 'Normal' -Message ""
Write-Log -Level 'Normal' -Message "System scanner"
Write-Log -Level 'Normal' -Message "=============="
Write-Log -Level 'Normal' -Message ""

foreach ($drive in $drives) {
    $driveRoot = "$($drive.DeviceID)\"
    $driveLabel = if ($drive.VolumeName) { "$($drive.DeviceID) ($($drive.VolumeName))" } else { $drive.DeviceID }

    Write-Log -Level 'Normal' -Message "Scanning drive $driveLabel ..."

    $activityId = [int]([char]$drive.DeviceID.Substring(0,1))

    Get-AllFoldersBreadthFirst -RootPath $driveRoot | ForEach-Object {
        $folder = $_

        if ($VerbosityLevel -eq 'Debug') {
            Write-Progress -Id $activityId `
                -Activity "Scanning $driveLabel" `
                -Status "Current folder" `
                -CurrentOperation $folder `
                -PercentComplete -1
        }

        if ($VerbosityLevel -eq 'Debug') {
            Write-Log -Level 'Debug' -Message "Folder: $folder"
        }

        foreach ($scanner in $resolvedScanners) {
            $scannerName = Split-Path $scanner -Leaf

            Write-Log -Level 'Detailed' -Message "  [$scannerName] $folder"

            try {
                $results = & $scanner -ScanPath $folder -VerbosityLevel $VerbosityLevel

                if ($results) {
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

                if ($VerbosityLevel -in @('Detailed','Debug')) {
                    Write-Log -Level 'Debug' -Message "Scanner error in $folder : $($_.Exception.Message)"
                }
            }
        }
    }

    if ($VerbosityLevel -eq 'Debug') {
        Write-Progress -Id $activityId -Activity "Scanning $driveLabel" -Completed
    }
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

$summary = foreach ($drive in ($drives | Select-Object -ExpandProperty DeviceID)) {
    $driveItems = @($sortedFindings | Where-Object { $_.Drive -eq $drive })

    [pscustomobject]@{
        Drive  = $drive
        High   = @($driveItems | Where-Object { $_.Severity -eq 'HIGH' }).Count
        Medium = @($driveItems | Where-Object { $_.Severity -eq 'Medium' }).Count
        Info   = @($driveItems | Where-Object { $_.Severity -eq 'Info' }).Count
        Total  = $driveItems.Count
        Status = if (@($driveItems | Where-Object { $_.Severity -eq 'HIGH' }).Count -gt 0) {
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