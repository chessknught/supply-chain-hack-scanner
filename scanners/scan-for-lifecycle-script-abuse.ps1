# © 2026 Sooke Software — Ted Neustaedter. All rights reserved.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScanPath,

    [int]$VerbosityLevel = 0
)

$ErrorActionPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# Lifecycle script hooks to inspect in package.json.
# Add new hook names here as the npm lifecycle model evolves.
# ---------------------------------------------------------------------------
$LifecycleScriptKeys = @(
    'preinstall'
    'install'
    'postinstall'
    'prepare'
    'prepublishOnly'
)

# ---------------------------------------------------------------------------
# Suspicious pattern definitions.
# Add new patterns here as new attack techniques are discovered.
#
# Fields:
#   Pattern  — .NET regex (evaluated case-insensitively via RegexOptions)
#   Label    — Human-readable description used in findings
#   Severity — 'Info' | 'Medium' | 'HIGH'
#
# Severity escalation rules (applied in Get-EffectiveSeverity):
#   - Any HIGH match             → HIGH
#   - Two or more Medium matches → HIGH  (combined suspicious indicators)
#   - One Medium match           → Medium
#   - All Info or no matches     → Info
# ---------------------------------------------------------------------------
$SuspiciousPatterns = @(

    # Shell launchers
    @{ Pattern = 'power' + 'shell(?:\s|\.exe|$|-[a-zA-Z])'; Label = 'PowerShell invocation';      Severity = 'Medium' }
    @{ Pattern = 'pw' + 'sh(?:\s|\.exe|$|-[a-zA-Z])';       Label = 'pwsh invocation';            Severity = 'Medium' }
    @{ Pattern = 'cmd\s*/c';                                 Label = 'cmd /c shell execution';     Severity = 'Medium' }
    @{ Pattern = 'bash\s+-c';                                Label = 'bash -c shell execution';    Severity = 'Medium' }
    @{ Pattern = 'sh\s+-c';                                  Label = 'sh -c shell execution';      Severity = 'Medium' }
    @{ Pattern = 'node\s+-e';                                Label = 'node -e code execution';     Severity = 'Medium' }

    # File download utilities
    @{ Pattern = '\bcurl\b';                                 Label = 'curl download utility';      Severity = 'Medium' }
    @{ Pattern = '\bwget\b';                                 Label = 'wget download utility';      Severity = 'Medium' }
    @{ Pattern = 'Invoke-Web' + 'Request|\biwr\b';           Label = 'PS web request cmdlet';      Severity = 'Medium' }
    @{ Pattern = '\bcert' + 'util\b';                        Label = 'certutil binary';            Severity = 'Medium' }
    @{ Pattern = '\bbits' + 'admin\b';                       Label = 'bits transfer tool';         Severity = 'HIGH'   }

    # Dangerous system binaries
    @{ Pattern = '\bmsh' + 'ta\b';                           Label = 'HTML application host';      Severity = 'HIGH'   }
    @{ Pattern = '\brun' + 'dll32\b';                        Label = 'DLL runner binary';          Severity = 'HIGH'   }
    @{ Pattern = '\bregsv' + 'r32\b';                        Label = 'COM registration binary';    Severity = 'HIGH'   }
    @{ Pattern = '\bcscri' + 'pt\b';                         Label = 'COM script host (C)';        Severity = 'HIGH'   }
    @{ Pattern = '\bwscri' + 'pt\b';                         Label = 'COM script host (W)';        Severity = 'HIGH'   }
    @{ Pattern = 'Start' + '-Process';                       Label = 'PS process launcher';        Severity = 'Medium' }

    # Package runner abuse
    @{ Pattern = '\bnpm\s+exec\b';                           Label = 'npm exec';                   Severity = 'Medium' }
    @{ Pattern = '\bnpx\b';                                  Label = 'npx execution';              Severity = 'Medium' }

    # Obfuscation and encoding
    @{ Pattern = '\bev' + 'al\s*\(';                         Label = 'eval call';                  Severity = 'HIGH'   }
    @{ Pattern = 'From' + 'Base' + '64String';               Label = 'PS Base64 decode function';  Severity = 'HIGH'   }
    @{ Pattern = '\bbase64\b';                               Label = 'base64 reference';           Severity = 'Medium' }
    @{ Pattern = '\bat' + 'ob\s*\(';                         Label = 'atob decode call';           Severity = 'HIGH'   }
    @{ Pattern = '\bbtoa\s*\(';                              Label = 'btoa encode call';           Severity = 'Medium' }

    # Process spawning (Node.js)
    @{ Pattern = 'child' + '_' + 'process';                  Label = 'child process module';       Severity = 'Medium' }
    @{ Pattern = '\bexec\s*\(';                              Label = 'exec call';                  Severity = 'Medium' }
    @{ Pattern = '\bspawn\s*\(';                             Label = 'spawn call';                 Severity = 'Medium' }

    # Hidden / silent execution
    @{ Pattern = '-WindowStyle\s+[Hh]idden|-w\s+[Hh]idden'; Label = 'hidden window flag';         Severity = 'HIGH'   }
    @{ Pattern = 'WindowStyle\s*=\s*[''"]?[Hh]idden';        Label = 'hidden window property';     Severity = 'HIGH'   }

    # Exfiltration endpoints
    @{ Pattern = 'disc' + 'ord\.com/api/web' + 'hooks';      Label = 'messaging webhook URL';      Severity = 'HIGH'   }
    @{ Pattern = 'api\.telegram\.org/bot';                   Label = 'bot API URL';                Severity = 'HIGH'   }

    # Suspicious URL forms
    @{ Pattern = 'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'; Label = 'raw IP address URL';    Severity = 'HIGH'   }
    @{ Pattern = 'https?://';                                Label = 'URL in lifecycle script';    Severity = 'Medium' }

)

# ---------------------------------------------------------------------------
# Helper: safely parse a JSON file. Returns $null on any parse or I/O error.
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
# Helper: create and append a finding to a list.
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
# Helper: test a lifecycle script value against all $SuspiciousPatterns.
# Returns a list of matched pattern hashtables.
# Uses [regex]::IsMatch to avoid polluting the $Matches automatic variable.
# ---------------------------------------------------------------------------
function Get-PatternHits {
    param([string]$ScriptValue)

    $hits = New-Object 'System.Collections.Generic.List[object]'

    foreach ($entry in $SuspiciousPatterns) {
        if ([regex]::IsMatch($ScriptValue, $entry.Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
            $hits.Add($entry)
        }
    }
    # Return as a plain .NET array so the caller always receives an array,
    # regardless of element count.
    $hits.ToArray()
}

# ---------------------------------------------------------------------------
# Helper: compute the effective severity from a collection of matched patterns.
#
# Escalation rules:
#   1. Any HIGH match             → HIGH
#   2. Two or more Medium matches → HIGH  (multiple suspicious indicators combined)
#   3. One Medium match           → Medium
#   4. Otherwise                  → Info
# ---------------------------------------------------------------------------
function Get-EffectiveSeverity {
    param($Hits)

    $highCount   = ($Hits | Where-Object { $_.Severity -eq 'HIGH'   } | Measure-Object).Count
    $mediumCount = ($Hits | Where-Object { $_.Severity -eq 'Medium' } | Measure-Object).Count

    if ($highCount   -ge 1) { return 'HIGH'   }
    if ($mediumCount -ge 2) { return 'HIGH'   }
    if ($mediumCount -eq 1) { return 'Medium' }
    return 'Info'
}

# ---------------------------------------------------------------------------
# Main scan body
# ---------------------------------------------------------------------------
$results = New-Object 'System.Collections.Generic.List[object]'

$pkgJsonPath = Join-Path $ScanPath 'package.json'

if (Test-Path -LiteralPath $pkgJsonPath -PathType Leaf) {

    $json = Get-JsonFile -Path $pkgJsonPath

    if ($json -and $json.scripts) {

        $pkgName    = if ($json.name)    { [string]$json.name    } else { '' }
        $pkgVersion = if ($json.version) { [string]$json.version } else { '' }

        foreach ($key in $LifecycleScriptKeys) {

            if ($json.scripts.PSObject.Properties.Name -notcontains $key) {
                continue
            }

            $scriptValue = [string]$json.scripts.$key

            if ([string]::IsNullOrWhiteSpace($scriptValue)) {
                continue
            }

            $hits = @(Get-PatternHits -ScriptValue $scriptValue)

            if ($hits.Count -eq 0) {
                # Lifecycle hook exists but nothing suspicious was detected — informational.
                Add-Finding `
                    -List           $results `
                    -Severity       'Info' `
                    -Type           'LifecycleScript' `
                    -Path           $pkgJsonPath `
                    -PackageName    $pkgName `
                    -Version        $pkgVersion `
                    -Indicator      "Lifecycle script '$key' present — no suspicious patterns detected" `
                    -Evidence       "scripts.$key`: $scriptValue" `
                    -Recommendation 'Verify that this lifecycle script is expected and has not been tampered with.'
            }
            else {
                $effectiveSeverity = Get-EffectiveSeverity -Hits $hits
                $matchedLabels     = ($hits | ForEach-Object { $_.Label }) -join '; '
                $findingType       = if ($effectiveSeverity -ne 'Info') { 'LifecycleScriptAbuse' } else { 'LifecycleScript' }
                $recommendation    = switch ($effectiveSeverity) {
                    'HIGH'   { 'Investigate immediately. This lifecycle script contains strong indicators of malicious or highly suspicious behaviour.' }
                    'Medium' { 'Manually inspect this lifecycle script. The patterns detected may indicate malicious activity.' }
                    default  { 'Verify that this lifecycle script is expected and has not been tampered with.' }
                }

                Add-Finding `
                    -List           $results `
                    -Severity       $effectiveSeverity `
                    -Type           $findingType `
                    -Path           $pkgJsonPath `
                    -PackageName    $pkgName `
                    -Version        $pkgVersion `
                    -Indicator      "Lifecycle script '$key' — matched: $matchedLabels" `
                    -Evidence       "scripts.$key`: $scriptValue" `
                    -Recommendation $recommendation
            }
        }
    }
}

$results
