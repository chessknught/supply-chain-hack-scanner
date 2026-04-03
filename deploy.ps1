# © 2026 Sooke Software — Ted Neustaedter.
# Licensed under the GNU General Public License, version 3 or later.
#
# deploy.ps1 — copies the scanner to remote hosts over SCP.
#
# Usage:
#   .\deploy.ps1
#   .\deploy.ps1 -User someuser
#   .\deploy.ps1 -Hosts @('10.0.0.100') -RemotePath '~/mydir'

[CmdletBinding()]
param(
    [string[]]$Hosts      = @('10.0.0.100', '10.0.0.101'),
    [string]  $User       = 'tneustaedter',
    [string]  $RemotePath = '~/scanner'
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Command scp -ErrorAction SilentlyContinue)) {
    Write-Error "scp is not available on PATH. Install OpenSSH or add it to PATH."
    exit 1
}

$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path

# Files and folders to deploy (relative to repo root)
$DeployItems = @(
    'scan-system.ps1'
    'scan-system.sh'
    'VERSION'
    'README.md'
    'scanners'
)

$success = $true

foreach ($target in $Hosts) {
    Write-Host ""
    Write-Host "Deploying to ${User}@${target}:${RemotePath} ..." -ForegroundColor Cyan

    # Ensure remote directory exists
    Write-Host "  Creating remote directory ..."
    ssh "${User}@${target}" "mkdir -p ${RemotePath}"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "  ERROR: could not create remote directory on $target" -ForegroundColor Red
        $success = $false
        continue
    }

    # Copy each item
    foreach ($item in $DeployItems) {
        $localPath = Join-Path $ScriptRoot $item
        if (-not (Test-Path -LiteralPath $localPath)) {
            Write-Host "  SKIP: $item (not found locally)" -ForegroundColor DarkGray
            continue
        }

        Write-Host "  Copying $item ..."
        $isDir = (Get-Item -LiteralPath $localPath) -is [System.IO.DirectoryInfo]
        if ($isDir) {
            scp -r "${localPath}" "${User}@${target}:${RemotePath}/"
        } else {
            scp "${localPath}" "${User}@${target}:${RemotePath}/"
        }

        if ($LASTEXITCODE -ne 0) {
            Write-Host "  ERROR: failed to copy $item to $target" -ForegroundColor Red
            $success = $false
        }
    }

    # Make shell scripts executable
    Write-Host "  Setting execute permissions on .sh files ..."
    ssh "${User}@${target}" "chmod +x ${RemotePath}/*.sh ${RemotePath}/scanners/*.sh 2>/dev/null; true"

    if ($success) {
        Write-Host "  Done." -ForegroundColor Green
    }
}

Write-Host ""
if ($success) {
    Write-Host "Deploy complete." -ForegroundColor Green
} else {
    Write-Host "Deploy finished with errors." -ForegroundColor Red
    exit 1
}
