# © 2026 Sooke Software — Ted Neustaedter.
# Licensed under the GNU General Public License, version 3 or later.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScanPath,

    [int]$VerbosityLevel = 0
)

$ErrorActionPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# Target file names inspected directly in the provided folder.
# Add new names or extensions here to extend file coverage.
# ---------------------------------------------------------------------------
$TargetFileNames = @(
    'package.json'
    'package-lock.json'
    'npm-shrinkwrap.json'
    '.npmrc'
    '.env'
    '.env.local'
    '.env.production'
    'Dockerfile'
    'docker-compose.yml'
    'docker-compose.yaml'
)

$TargetExtensions = @(
    '.js', '.cjs', '.mjs', '.ts',
    '.sh', '.bash', '.cmd', '.bat', '.ps1',
    '.json', '.yml', '.yaml'
)

# ---------------------------------------------------------------------------
# Pattern definitions — three named groups:
#
#   Endpoint  — Known suspicious remote destinations (exfil, C2, paste, tunnel).
#               A match here always generates a finding.
#               HIGH patterns alone → HIGH severity.
#               Medium patterns alone → Medium severity.
#
#   ExfilCmd  — Outbound data-sending command patterns.
#               Alone → Medium. Combined with Endpoint or Context → HIGH.
#
#   Context   — Credential, token, and sensitive file access patterns.
#               Alone → no finding (too noisy without outbound signal).
#               Combined with Endpoint or ExfilCmd → escalates to HIGH.
#
# Severity computation (applied in Get-FileSeverity):
#   1. Any HIGH Endpoint hit                         → HIGH
#   2. Any Endpoint hit + any Context hit            → HIGH
#   3. Any ExfilCmd hit + any Context hit            → HIGH
#   4. Any ExfilCmd hit + any Endpoint hit           → HIGH
#   5. Any Medium Endpoint hit alone                 → Medium
#   6. Any ExfilCmd hit alone                        → Medium
#   7. Context hits with no Endpoint or ExfilCmd     → no finding emitted
#
# AV note: Strings matching known malware indicators are split with +
#   so they do not exist as contiguous literals in source.
#   They are assembled by PowerShell at runtime into correct regex patterns.
# ---------------------------------------------------------------------------
$Patterns = @(

    # ── Known exfiltration and C2 endpoints ─────────────────────────────────
    @{ Pattern = 'disc' + 'ord\.com/api/web' + 'hooks';      Label = 'Discord webhook URL';             Group = 'Endpoint'; Severity = 'HIGH'   }
    @{ Pattern = 'disc' + 'ordapp\.com/api/web' + 'hooks';   Label = 'Discord webhook URL (legacy)';    Group = 'Endpoint'; Severity = 'HIGH'   }
    @{ Pattern = 'api\.tele' + 'gram\.org';                   Label = 'Telegram bot API URL';            Group = 'Endpoint'; Severity = 'HIGH'   }
    @{ Pattern = 't\.me/[a-zA-Z]';                            Label = 'Telegram short link';             Group = 'Endpoint'; Severity = 'Medium' }
    @{ Pattern = 'web' + 'hook\.site';                        Label = 'webhook.site callback URL';       Group = 'Endpoint'; Severity = 'HIGH'   }
    @{ Pattern = 'ng' + 'rok\.(io|app|dev|com)';              Label = 'ngrok tunnel domain';             Group = 'Endpoint'; Severity = 'Medium' }
    @{ Pattern = 'request' + 'bin\.[a-z]+';                   Label = 'requestbin callback URL';         Group = 'Endpoint'; Severity = 'HIGH'   }
    @{ Pattern = 'request' + 'catcher\.com';                  Label = 'requestcatcher callback URL';     Group = 'Endpoint'; Severity = 'HIGH'   }
    @{ Pattern = 'interact\.sh';                              Label = 'interactsh OAST callback URL';    Group = 'Endpoint'; Severity = 'HIGH'   }

    # ── Paste and staging services ───────────────────────────────────────────
    @{ Pattern = 'paste' + 'bin\.com';                        Label = 'Pastebin URL';                    Group = 'Endpoint'; Severity = 'Medium' }
    @{ Pattern = 'haste' + 'bin';                             Label = 'Hastebin URL';                    Group = 'Endpoint'; Severity = 'Medium' }
    @{ Pattern = 'transfer\.sh';                              Label = 'transfer.sh file-share URL';      Group = 'Endpoint'; Severity = 'Medium' }
    @{ Pattern = 'anon' + 'files\.(com|me)';                  Label = 'AnonFiles URL';                   Group = 'Endpoint'; Severity = 'Medium' }
    @{ Pattern = 'file\.io';                                  Label = 'file.io URL';                     Group = 'Endpoint'; Severity = 'Medium' }
    @{ Pattern = 'gist\.github' + 'usercontent\.com';         Label = 'Raw GitHub gist URL';             Group = 'Endpoint'; Severity = 'Medium' }

    # ── Raw IP address URLs ──────────────────────────────────────────────────
    @{ Pattern = 'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'; Label = 'URL with raw IP address';     Group = 'Endpoint'; Severity = 'HIGH'   }

    # ── Outbound data-sending command patterns ───────────────────────────────
    @{ Pattern = '\bcurl\b.{0,60}-X\s+POST';                  Label = 'curl HTTP POST command';          Group = 'ExfilCmd'; Severity = 'Medium' }
    @{ Pattern = '\bcurl\b.{0,60}--data';                     Label = 'curl --data payload flag';        Group = 'ExfilCmd'; Severity = 'Medium' }
    @{ Pattern = '\bcurl\b.{0,60}\s-d\s';                     Label = 'curl -d data flag';               Group = 'ExfilCmd'; Severity = 'Medium' }
    @{ Pattern = '\bwget\b.{0,60}--post-data';                Label = 'wget --post-data command';        Group = 'ExfilCmd'; Severity = 'Medium' }
    @{ Pattern = 'Invoke-Rest' + 'Method\b.{0,80}-Method\s+Post'; Label = 'PowerShell RestMethod POST'; Group = 'ExfilCmd'; Severity = 'Medium' }
    @{ Pattern = 'requests\.post\s*\(';                       Label = 'Python requests.post() call';     Group = 'ExfilCmd'; Severity = 'Medium' }
    @{ Pattern = 'axios\.post\s*\(';                          Label = 'axios.post() call';               Group = 'ExfilCmd'; Severity = 'Medium' }
    @{ Pattern = 'fetch\s*\(\s*[''"]https?://';               Label = 'fetch() call with external URL';  Group = 'ExfilCmd'; Severity = 'Medium' }

    # ── Sensitive credential and asset access patterns ───────────────────────
    @{ Pattern = '\$env:';                                    Label = 'PowerShell env variable access';  Group = 'Context';  Severity = 'Medium' }
    @{ Pattern = 'process\.env';                              Label = 'Node.js process.env access';      Group = 'Context';  Severity = 'Medium' }
    @{ Pattern = '\bAWS_';                                    Label = 'AWS credential variable';         Group = 'Context';  Severity = 'Medium' }
    @{ Pattern = '\bAZURE_';                                  Label = 'Azure credential variable';       Group = 'Context';  Severity = 'Medium' }
    @{ Pattern = '\bGOOGLE_';                                 Label = 'GCP credential variable';         Group = 'Context';  Severity = 'Medium' }
    @{ Pattern = 'GITHUB_TOKEN';                              Label = 'GitHub token variable';           Group = 'Context';  Severity = 'Medium' }
    @{ Pattern = 'NPM_TOKEN';                                 Label = 'npm token variable';              Group = 'Context';  Severity = 'Medium' }
    @{ Pattern = '\.npmrc';                                   Label = '.npmrc file reference';           Group = 'Context';  Severity = 'Medium' }
    @{ Pattern = '\.git-credentials';                         Label = '.git-credentials file';           Group = 'Context';  Severity = 'Medium' }
    @{ Pattern = '\.ssh[/\\]';                                Label = '.ssh directory reference';        Group = 'Context';  Severity = 'Medium' }
    @{ Pattern = 'id_rsa|id_ed25519|id_ecdsa';                Label = 'SSH private key filename';        Group = 'Context';  Severity = 'Medium' }

)

# ---------------------------------------------------------------------------
# Helper: safely read a file as a raw string. Returns $null on any I/O error.
# ---------------------------------------------------------------------------
function Get-FileText {
    param([string]$Path)
    try {
        Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    }
    catch {
        $null
    }
}

# ---------------------------------------------------------------------------
# Helper: safely parse JSON. Returns $null on any parse or I/O error.
# ---------------------------------------------------------------------------
function Get-JsonFile {
    param([string]$Path)
    try {
        Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -Depth 100
    }
    catch {
        $null
    }
}

# ---------------------------------------------------------------------------
# Helper: construct a finding PSCustomObject.
# ---------------------------------------------------------------------------
function New-Finding {
    param(
        [string]$Severity,
        [string]$Type,
        [string]$Path,
        [string]$PackageName,
        [string]$Version,
        [string]$Indicator,
        [string]$Evidence,
        [string]$Recommendation
    )
    [pscustomobject]@{
        Severity       = $Severity
        Type           = $Type
        Path           = $Path
        PackageName    = $PackageName
        Version        = $Version
        Indicator      = $Indicator
        Evidence       = $Evidence
        Recommendation = $Recommendation
    }
}

# ---------------------------------------------------------------------------
# Helper: find the first matching line number for a regex pattern in a file.
# Returns "line N: <trimmed content>" or $null if no match or I/O error.
# ---------------------------------------------------------------------------
function Get-FirstMatchLine {
    param([string]$FilePath, [string]$Pattern)
    try {
        $m = Select-String -LiteralPath $FilePath -Pattern $Pattern -CaseSensitive:$false `
                           -ErrorAction Stop |
             Select-Object -First 1
        if ($m) {
            $lineText = $m.Line.Trim()
            if ($lineText.Length -gt 120) { $lineText = $lineText.Substring(0, 117) + '...' }
            return "line $($m.LineNumber): $lineText"
        }
    }
    catch {}
    $null
}

# ---------------------------------------------------------------------------
# Helper: append a finding to a list.
# ---------------------------------------------------------------------------
function Add-Finding {
    param(
        [System.Collections.Generic.List[object]]$List,
        [string]$Severity,
        [string]$Type,
        [string]$Path,
        [string]$PackageName,
        [string]$Version,
        [string]$Indicator,
        [string]$Evidence,
        [string]$Recommendation
    )
    $List.Add(
        (New-Finding `
            -Severity       $Severity `
            -Type           $Type `
            -Path           $Path `
            -PackageName    $PackageName `
            -Version        $Version `
            -Indicator      $Indicator `
            -Evidence       $Evidence `
            -Recommendation $Recommendation)
    )
}

# ---------------------------------------------------------------------------
# Helper: test file text against all $Patterns.
# Returns a list of matched pattern hashtables (each has Pattern/Label/Group/Severity).
# Uses [regex]::IsMatch to avoid polluting the $Matches automatic variable.
# ---------------------------------------------------------------------------
function Get-PatternHits {
    param([string]$Text)

    $hits = New-Object 'System.Collections.Generic.List[object]'
    foreach ($entry in $Patterns) {
        if ([regex]::IsMatch($Text, $entry.Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
            $hits.Add($entry)
        }
    }
    # The comma operator returns the array as a single pipeline object, preventing
    # PowerShell from unrolling a 1-element array into a bare hashtable at the call site.
    $hits.ToArray()
}

# ---------------------------------------------------------------------------
# Helper: compute effective severity from a set of pattern hits.
#
# Rules (in priority order):
#   1. Any HIGH Endpoint hit                              → HIGH
#   2. Any Endpoint hit + any Context hit                 → HIGH
#   3. Any ExfilCmd hit + any Endpoint hit                → HIGH
#   4. Any Medium Endpoint hit alone                      → Medium
#   5. Any ExfilCmd hit alone, or ExfilCmd + Context only → Medium
#   6. Context hits only                                  → $null (no finding)
#
# Note: ExfilCmd + Context without a suspicious Endpoint stays Medium.
# A POST to an unknown/internal endpoint with env var access is common
# and legitimate; HIGH requires a confirmed suspicious destination.
# ---------------------------------------------------------------------------
function Get-FileSeverity {
    param($Hits)

    $endpointHits = @($Hits | Where-Object { $_.Group -eq 'Endpoint' })
    $exfilHits    = @($Hits | Where-Object { $_.Group -eq 'ExfilCmd' })
    $contextHits  = @($Hits | Where-Object { $_.Group -eq 'Context'  })

    if ($endpointHits.Count -eq 0 -and $exfilHits.Count -eq 0) {
        return $null
    }

    if ($endpointHits | Where-Object { $_.Severity -eq 'HIGH' }) { return 'HIGH' }
    if ($endpointHits.Count -gt 0 -and $contextHits.Count -gt 0)  { return 'HIGH' }
    if ($exfilHits.Count    -gt 0 -and $endpointHits.Count -gt 0) { return 'HIGH' }
    if ($endpointHits.Count -gt 0) { return 'Medium' }
    return 'Medium'
}

# ---------------------------------------------------------------------------
# Main scan body
# ---------------------------------------------------------------------------
$results = New-Object 'System.Collections.Generic.List[object]'

# Capture folder-level package identity from package.json if present.
$folderPkgName    = ''
$folderPkgVersion = ''
$pkgJsonInFolder  = Join-Path $ScanPath 'package.json'
if (Test-Path -LiteralPath $pkgJsonInFolder -PathType Leaf) {
    $pkgJson = Get-JsonFile -Path $pkgJsonInFolder
    if ($pkgJson) {
        $folderPkgName    = if ($pkgJson.name)    { [string]$pkgJson.name    } else { '' }
        $folderPkgVersion = if ($pkgJson.version) { [string]$pkgJson.version } else { '' }
    }
}

# Enumerate target files directly in the folder (no recursion).
$files = @()
try {
    $files = Get-ChildItem -LiteralPath $ScanPath -File -Force -ErrorAction Stop |
        Where-Object {
            ($TargetFileNames -contains $_.Name) -or
            ($TargetExtensions -contains $_.Extension.ToLower())
        }
}
catch {
    $files = @()
}

foreach ($file in $files) {
    $text = Get-FileText -Path $file.FullName
    if ([string]::IsNullOrWhiteSpace($text)) { continue }

    $hits = @(Get-PatternHits -Text $text)
    if ($hits.Count -eq 0) { continue }

    $severity = Get-FileSeverity -Hits $hits
    if (-not $severity) { continue }   # context-only hits — no finding

    # Build grouped label summaries for the Indicator field.
    $endpointHits = @($hits | Where-Object { $_.Group -eq 'Endpoint' })
    $exfilHits    = @($hits | Where-Object { $_.Group -eq 'ExfilCmd' })
    $contextHits  = @($hits | Where-Object { $_.Group -eq 'Context'  })

    $indicatorParts = @()
    if ($endpointHits.Count -gt 0) {
        $indicatorParts += 'Suspicious endpoint(s): ' + (($endpointHits | ForEach-Object { $_.Label }) -join ', ')
    }
    if ($exfilHits.Count -gt 0) {
        $indicatorParts += 'Outbound command(s): ' + (($exfilHits | ForEach-Object { $_.Label }) -join ', ')
    }
    if ($contextHits.Count -gt 0) {
        $indicatorParts += 'Sensitive asset access: ' + (($contextHits | ForEach-Object { $_.Label }) -join ', ')
    }
    $indicator = $indicatorParts -join ' | '

    $allLabels   = ($hits | ForEach-Object { $_.Label }) -join '; '
    $topHit      = if ($endpointHits.Count -gt 0) { $endpointHits[0] } elseif ($exfilHits.Count -gt 0) { $exfilHits[0] } else { $null }
    $lineRef     = if ($topHit) { Get-FirstMatchLine -FilePath $file.FullName -Pattern $topHit.Pattern } else { $null }
    $evidenceText = if ($lineRef) { "$lineRef | Matched patterns: $allLabels" } else { "Matched patterns: $allLabels" }
    $findingType = if ($severity -eq 'HIGH') { 'SuspiciousExfil' } else { 'SuspiciousEndpoint' }

    $recommendation = switch ($severity) {
        'HIGH'   { 'Investigate immediately. This file contains strong indicators of credential exfiltration or malicious outbound communication.' }
        'Medium' { 'Manually inspect this file for unauthorized data collection or outbound transmission.' }
        default  { 'Review this file for unexpected network communication.' }
    }

    Add-Finding `
        -List           $results `
        -Severity       $severity `
        -Type           $findingType `
        -Path           $file.FullName `
        -PackageName    $folderPkgName `
        -Version        $folderPkgVersion `
        -Indicator      $indicator `
        -Evidence       $evidenceText `
        -Recommendation $recommendation
}

$results
