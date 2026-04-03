# © 2026 Sooke Software — Ted Neustaedter.
# Licensed under the GNU General Public License, version 3 or later.
#
# scan-for-obfuscation-staged-loaders.ps1 — scans a single folder
# (non-recursive) for local heuristic indicators of encoded payload handling,
# staged loading, hidden execution, temp-file staging, and download-to-run flows.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScanPath,

    [int]$VerbosityLevel = 0
)

$ErrorActionPreference = 'SilentlyContinue'

$ExactTargetFiles = @(
    'package.json',
    'package-lock.json',
    'npm-shrinkwrap.json',
    '.npmrc',
    '.env',
    '.env.local',
    '.env.production',
    'Dockerfile',
    'docker-compose.yml',
    'docker-compose.yaml',
    'Makefile',
    'Jenkinsfile',
    'build.gradle',
    'pom.xml',
    'Cargo.toml',
    'requirements.txt',
    'pyproject.toml'
)

$TargetExtensions = @(
    '.js', '.cjs', '.mjs', '.ts',
    '.py', '.sh', '.bash', '.zsh',
    '.cmd', '.bat', '.ps1', '.psm1',
    '.json', '.yml', '.yaml',
    '.csproj', '.cs', '.go'
)

$LifecycleScriptKeys = @(
    'preinstall', 'install', 'postinstall', 'prepare',
    'prepublish', 'prepublishOnly', 'prepack', 'postpack'
)

$BaseEncodingFragment = 'base' + '64'
$FromEncodingFragment = 'from' + 'base' + '64string'
$AtobFragment = 'at' + 'ob'
$BtoaFragment = 'bt' + 'oa'
$PowerShellFragment = 'power' + 'shell'
$PwshFragment = 'pw' + 'sh'
$InvokeWebRequestFragment = 'invoke-web' + 'request'
$InvokeRestMethodFragment = 'invoke-rest' + 'method'
$InvokeExpressionFragment = 'invoke-exp' + 'ression|(?<![a-z])i' + 'ex(?![a-z])'
$EvalFragment = 'ev' + 'al'
$FunctionFragment = 'fu' + 'nction'
$SpawnFragment = 'sp' + 'awn'
$ChildProcessFragment = 'child' + '_' + 'process'
$StartProcessFragment = 'start' + '-process'
$FromCharCodeFragment = 'string\.from' + 'charcode'
$CertUtilFragment = 'cert' + 'util'

$EncodedPayloadRules = @(
    @{ Pattern = $FromEncodingFragment; Label = 'decode helper'; Weight = 2 },
    @{ Pattern = '\[convert\]::from' + 'base' + '64string'; Label = 'PowerShell decode helper'; Weight = 2 },
    @{ Pattern = $BaseEncodingFragment + '\s+-d\b'; Label = 'shell decode flag'; Weight = 2 },
    @{ Pattern = $AtobFragment + '\s*\('; Label = 'browser decode helper'; Weight = 2 },
    @{ Pattern = $BtoaFragment + '\s*\('; Label = 'browser encode helper'; Weight = 1 },
    @{ Pattern = 'buffer\.from\s*\([^\)]{0,120}' + $BaseEncodingFragment; Label = 'buffer decode helper'; Weight = 2 },
    @{ Pattern = $CertUtilFragment + '\s+-decode\b'; Label = 'system decode utility'; Weight = 2 },
    @{ Pattern = $PowerShellFragment + '\s+-e(?:n|nc)\b|' + $PwshFragment + '\s+-e(?:n|nc)\b'; Label = 'encoded shell launch'; Weight = 2 },
    @{ Pattern = $FromCharCodeFragment + '\s*\('; Label = 'charcode rebuild routine'; Weight = 2 },
    @{ Pattern = '\[char\[\]\]|\bchr\s*\('; Label = 'character reconstruction routine'; Weight = 2 },
    @{ Pattern = 'gzip|zlib|inflate|decompress'; Label = 'compression helper'; Weight = 1 },
    @{ Pattern = '\bxor\b|decrypt|decipher|rijndael|aes'; Label = 'string decode routine'; Weight = 1 }
)

$DynamicExecutionRules = @(
    @{ Pattern = $EvalFragment + '\s*\('; Label = 'dynamic evaluation'; Weight = 2 },
    @{ Pattern = 'new\s+' + $FunctionFragment + '\s*\(|(?<!new\s)' + $FunctionFragment + '\s*\('; Label = 'runtime function build'; Weight = 2 },
    @{ Pattern = $InvokeExpressionFragment; Label = 'PowerShell expression launch'; Weight = 2 },
    @{ Pattern = '\bexec\s*\(|' + $SpawnFragment + '\s*\(|' + $ChildProcessFragment; Label = 'process helper'; Weight = 2 },
    @{ Pattern = 'subprocess|os\.system|runtime\.getruntime\(\)\.exec'; Label = 'interpreter execution helper'; Weight = 2 },
    @{ Pattern = 'process\.start|' + $StartProcessFragment; Label = 'process start API'; Weight = 2 },
    @{ Pattern = 'bash\s+-c\b|sh\s+-c\b|cmd\s*/c\b|node\s+-e\b|python\s+-c\b'; Label = 'inline command launch'; Weight = 2 }
)

$DownloaderRules = @(
    @{ Pattern = '\bcurl\b|\bwget\b'; Label = 'web fetch utility'; Weight = 2 },
    @{ Pattern = $InvokeWebRequestFragment + '|' + $InvokeRestMethodFragment; Label = 'PowerShell web fetch'; Weight = 2 },
    @{ Pattern = 'requests\.get\s*\(|requests\.post\s*\('; Label = 'Python web request'; Weight = 2 },
    @{ Pattern = 'axios\.(?:get|post)\s*\(|fetch\s*\(|\brequest\s*\('; Label = 'JavaScript web request'; Weight = 2 },
    @{ Pattern = 'download(string|file)?|urlretrieve|webclient\.download'; Label = 'download helper'; Weight = 2 },
    @{ Pattern = '\bcurl\b[^\r\n|]{0,200}\|\s*(?:ba|z)?sh\b|\bwget\b[^\r\n|]{0,200}\|\s*(?:ba|z)?sh\b'; Label = 'pipe into shell'; Weight = 4 },
    @{ Pattern = $InvokeWebRequestFragment + '[^\r\n|]{0,200}\|\s*(?:' + $InvokeExpressionFragment + ')'; Label = 'PowerShell pipe into expression'; Weight = 4 },
    @{ Pattern = 'fetch\s*\([^\)]{0,200}\)\s*\.then\s*\([^\)]{0,200}' + $EvalFragment; Label = 'network response to evaluation'; Weight = 4 }
)

$HiddenExecutionRules = @(
    @{ Pattern = '-windowstyle\s+hidden|-w\s+hidden'; Label = 'hidden window flag'; Weight = 2 },
    @{ Pattern = $StartProcessFragment + '[^\r\n]{0,120}-windowstyle\s+hidden'; Label = 'hidden process start'; Weight = 3 },
    @{ Pattern = 'nohup\b|disown\b|detached\b|background'; Label = 'background launch'; Weight = 1 },
    @{ Pattern = 'schtasks|crontab|launchctl|startup'; Label = 'persistence helper'; Weight = 1 },
    @{ Pattern = 'execute\s+silently|run\s+hidden'; Label = 'stealth wording'; Weight = 1 }
)

$TempStagingRules = @(
    @{ Pattern = '[/\\](?:tmp|var/tmp)[/\\]|%temp%|\$env:temp|appdata[/\\]local[/\\]temp'; Label = 'temp path reference'; Weight = 2 },
    @{ Pattern = '\.(?:tmp|bin|dat)(?:''|"|\s|$)'; Label = 'staged temp artifact'; Weight = 1 },
    @{ Pattern = 'chmod\s+\+x|icacls|set-executionpolicy'; Label = 'execution enable step'; Weight = 2 },
    @{ Pattern = 'move-item|rename-item|\bmv\b|\bren\b'; Label = 'rename or move step'; Weight = 1 },
    @{ Pattern = 'mktemp|new-item|writeallbytes|set-content|out-file'; Label = 'payload write primitive'; Weight = 2 },
    @{ Pattern = '(?:^|[/\\])\.[a-z0-9_-]{4,24}\.(?:tmp|bin|dat)(?:$|[^a-z0-9])|(?:^|[/\\])[a-z0-9_-]{8,24}\.(?:tmp|bin|dat)(?:$|[^a-z0-9])'; Label = 'hidden staging filename'; Weight = 1 }
)

$ConstructionRules = @(
    @{ Pattern = '(?:["''][^"''\r\n]{1,12}["'']\s*(?:\+\s*["''][^"''\r\n]{1,12}["'']\s*){5,})'; Label = 'fragmented string assembly'; Weight = 2 },
    @{ Pattern = '(?:\[[^\]]{8,160}\]|array\s*\()[^\r\n]{0,80}join\s*\('; Label = 'array join construction'; Weight = 2 },
    @{ Pattern = 'hxxps?://|https?:\/\/[^\s\)''"]*\.replace\s*\('; Label = 'disguised or rebuilt address'; Weight = 2 },
    @{ Pattern = 'charcodeat|fromcharcode|replace\s*\([^\)]{0,120}(?:http|cmd|exe|dll|sh)'; Label = 'character or replace rebuild'; Weight = 2 },
    @{ Pattern = 'environment\.|process\.env|\$env:'; Label = 'environment-driven command build'; Weight = 1 }
)

$LoaderKeywordRules = @(
    @{ Pattern = '(?<![a-z])(loader|bootstrap|stub|stager|dropper|payload|shellcode|unpack|decrypt|decode)(?![a-z])'; Label = 'loader wording'; Weight = 1 },
    @{ Pattern = '(?<![a-z])stage\s*[12]|multi-?stage|second-?stage|self-?extract'; Label = 'staged flow wording'; Weight = 1 }
)

function Write-DebugLog {
    param([string]$Message)

    if ($VerbosityLevel -gt 0) {
        Write-Verbose $Message
    }
}

function Get-FileText {
    param([string]$Path)

    try {
        Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    }
    catch {
        $null
    }
}

function Get-JsonFile {
    param([string]$Path)

    try {
        Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 100
    }
    catch {
        $null
    }
}

function Get-ScanText {
    param([string]$Text)

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return ''
    }

    (($Text -split "`r?`n") | Where-Object {
        ($_ -notmatch '^\s*$') -and
        ($_ -notmatch '^\s*#') -and
        ($_ -notmatch '^\s*//') -and
        ($_ -notmatch '^\s*@\{\s*Pattern\s*=') -and
        ($_ -notmatch '^\s*\$[A-Za-z0-9_]+\s*=\s*@\(') -and
        ($_ -notmatch '^\s*\$[A-Za-z0-9_]+\s*=\s*''[^'']*''(?:\s*\+\s*''[^'']*'')+\s*$')
    }) -join "`n"
}

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

    $List.Add((New-Finding `
        -Severity $Severity `
        -Type $Type `
        -Path $Path `
        -PackageName $PackageName `
        -Version $Version `
        -Indicator $Indicator `
        -Evidence $Evidence `
        -Recommendation $Recommendation))
}

function Get-ProjectIdentity {
    param([string]$FolderPath)

    $pkgPath = Join-Path $FolderPath 'package.json'
    if (-not (Test-Path -LiteralPath $pkgPath -PathType Leaf)) {
        return @{ Name = ''; Version = '' }
    }

    $json = Get-JsonFile -Path $pkgPath
    if (-not $json) {
        return @{ Name = ''; Version = '' }
    }

    @{ Name = [string]$json.name; Version = [string]$json.version }
}

function Test-IsTargetFile {
    param([System.IO.FileInfo]$File)

    if ($ExactTargetFiles -contains $File.Name) {
        return $true
    }

    $TargetExtensions -contains $File.Extension
}

function Get-RuleHits {
    param(
        [string]$Text,
        [object[]]$Rules
    )

    $hits = New-Object 'System.Collections.Generic.List[object]'
    foreach ($rule in $Rules) {
        if ([regex]::IsMatch($Text, $rule.Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
            $hits.Add($rule)
        }
    }

    $hits.ToArray()
}

function Get-BlobHits {
    param([string]$Text)

    $blobRules = @(
        @{ Pattern = '(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{140,}={0,2}(?![A-Za-z0-9+/=])'; Label = 'long encoded blob'; Weight = 2 },
        @{ Pattern = '(?<![A-Fa-f0-9])[A-Fa-f0-9]{160,}(?![A-Fa-f0-9])'; Label = 'long hex blob'; Weight = 2 },
        @{ Pattern = '(?:\\x[0-9A-Fa-f]{2}){24,}|(?:\\u[0-9A-Fa-f]{4}){12,}'; Label = 'escaped byte blob'; Weight = 2 }
    )

    @(Get-RuleHits -Text $Text -Rules $blobRules)
}

function Get-HitWeight {
    param($Hits)

    $sum = 0
    foreach ($hit in $Hits) {
        $sum += [int]$hit.Weight
    }
    $sum
}

function Get-HitLabels {
    param(
        $Hits,
        [int]$MaxCount = 6
    )

    if (-not $Hits -or $Hits.Count -eq 0) {
        return ''
    }

    (($Hits | ForEach-Object { $_.Label } | Select-Object -Unique | Select-Object -First $MaxCount) -join '; ')
}

function Get-PackageScriptContext {
    param([string]$PackageJsonPath)

    $json = Get-JsonFile -Path $PackageJsonPath
    if (-not $json -or -not $json.scripts) {
        return @{ Keys = @(); Summary = '' }
    }

    $matchedKeys = New-Object 'System.Collections.Generic.List[string]'
    foreach ($key in $LifecycleScriptKeys) {
        if ($json.scripts.PSObject.Properties.Name -notcontains $key) {
            continue
        }

        $scriptValue = [string]$json.scripts.$key
        if ([string]::IsNullOrWhiteSpace($scriptValue)) {
            continue
        }

        $combinedHits = @(
            Get-RuleHits -Text $scriptValue -Rules $EncodedPayloadRules
            Get-RuleHits -Text $scriptValue -Rules $DynamicExecutionRules
            Get-RuleHits -Text $scriptValue -Rules $DownloaderRules
            Get-RuleHits -Text $scriptValue -Rules $HiddenExecutionRules
            Get-RuleHits -Text $scriptValue -Rules $TempStagingRules
            Get-RuleHits -Text $scriptValue -Rules $ConstructionRules
            Get-RuleHits -Text $scriptValue -Rules $LoaderKeywordRules
            Get-BlobHits -Text $scriptValue
        )

        if ($combinedHits.Count -gt 0) {
            $matchedKeys.Add($key)
        }
    }

    @{ Keys = $matchedKeys.ToArray(); Summary = ($matchedKeys -join ', ') }
}

function Get-Recommendation {
    param([string]$Severity)

    switch ($Severity) {
        'HIGH' {
            'Investigate immediately. This file combines staged loading or encoded content with execution behavior consistent with a downloader or loader.'
        }
        'Medium' {
            'Review this file closely. The combined heuristics suggest obfuscation, generated execution, or staged loading behavior worth triage.'
        }
        default {
            'Review in context. The signals are weak on their own but may point to obfuscated or staged execution logic.'
        }
    }
}

function Analyze-File {
    param(
        [System.IO.FileInfo]$File,
        [string]$PackageName,
        [string]$PackageVersion
    )

    $text = Get-FileText -Path $File.FullName
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    $scanText = Get-ScanText -Text $text
    if ([string]::IsNullOrWhiteSpace($scanText) -and $File.Name -ne 'package.json') {
        return $null
    }

    $encodedHits = @(Get-RuleHits -Text $scanText -Rules $EncodedPayloadRules)
    $blobHits = @(Get-BlobHits -Text $scanText)
    $dynamicHits = @(Get-RuleHits -Text $scanText -Rules $DynamicExecutionRules)
    $downloaderHits = @(Get-RuleHits -Text $scanText -Rules $DownloaderRules)
    $hiddenHits = @(Get-RuleHits -Text $scanText -Rules $HiddenExecutionRules)
    $tempHits = @(Get-RuleHits -Text $scanText -Rules $TempStagingRules)
    $constructionHits = @(Get-RuleHits -Text $scanText -Rules $ConstructionRules)
    $keywordHits = @(Get-RuleHits -Text $scanText -Rules $LoaderKeywordRules)

    $hasEncoding = ($encodedHits.Count + $blobHits.Count) -gt 0
    $hasDynamic = $dynamicHits.Count -gt 0
    $hasDownloader = $downloaderHits.Count -gt 0
    $hasHidden = $hiddenHits.Count -gt 0
    $hasTemp = $tempHits.Count -gt 0
    $hasConstruction = $constructionHits.Count -gt 0
    $hasKeywords = $keywordHits.Count -gt 0

    if (-not ($hasEncoding -or $hasDynamic -or $hasDownloader -or $hasHidden -or $hasTemp -or $hasConstruction -or $hasKeywords)) {
        return $null
    }

    $score = 0
    $score += Get-HitWeight -Hits $encodedHits
    $score += Get-HitWeight -Hits $blobHits
    $score += Get-HitWeight -Hits $dynamicHits
    $score += Get-HitWeight -Hits $downloaderHits
    $score += Get-HitWeight -Hits $hiddenHits
    $score += Get-HitWeight -Hits $tempHits
    $score += Get-HitWeight -Hits $constructionHits
    $score += Get-HitWeight -Hits $keywordHits

    if (($encodedHits.Count + $blobHits.Count) -ge 2) { $score += 1 }
    if ($hasEncoding -and $hasDynamic) { $score += 3 }
    if ($hasDownloader -and $hasDynamic) { $score += 4 }
    if ($hasDownloader -and $hasTemp) { $score += 3 }
    if ($hasHidden -and ($hasDownloader -or $hasDynamic)) { $score += 2 }
    if ($hasConstruction -and ($hasEncoding -or $hasDownloader -or $hasDynamic)) { $score += 2 }
    if ($hasTemp -and $hasDynamic) { $score += 2 }

    $strongCategoryCount = @($hasEncoding, $hasDynamic, $hasDownloader, $hasHidden, $hasTemp, $hasConstruction | Where-Object { $_ }).Count
    if ($strongCategoryCount -ge 3) { $score += 2 }

    $scriptContext = @{ Keys = @(); Summary = '' }
    if ($File.Name -eq 'package.json') {
        $scriptContext = Get-PackageScriptContext -PackageJsonPath $File.FullName
        if ($scriptContext.Keys.Count -gt 0 -and ($hasEncoding -or $hasDynamic -or $hasDownloader)) {
            $score += 3
        }
    }
    elseif ($File.Name -in @('Dockerfile', 'Makefile', 'Jenkinsfile')) {
        if (($hasDownloader -or $hasDynamic) -and ($hasEncoding -or $hasTemp -or $hasConstruction)) {
            $score += 2
        }
    }

    $highConfidence = (
        ($hasDownloader -and $hasDynamic) -or
        ($hasEncoding -and $hasDynamic -and ($hasDownloader -or $hasTemp -or $hasConstruction)) -or
        ($hasDownloader -and $hasTemp -and ($hasDynamic -or $hasEncoding -or $hasHidden)) -or
        ($hasDownloader -and $hasHidden) -or
        ($hasTemp -and $hasDynamic -and $hasEncoding) -or
        ($scriptContext.Keys.Count -gt 0 -and ($hasDownloader -or ($hasEncoding -and $hasDynamic)))
    )

    $severity = if ($highConfidence) {
        'HIGH'
    }
    elseif (
        $hasDownloader -or
        ($hasDynamic -and ($hasEncoding -or $hasConstruction -or $hasTemp -or $hasHidden)) -or
        ($hasEncoding -and ($hasDynamic -or $hasDownloader -or $hasConstruction)) -or
        ($hasHidden -and ($hasDownloader -or $hasDynamic)) -or
        ($hasTemp -and ($hasDownloader -or $hasDynamic)) -or
        ($scriptContext.Keys.Count -gt 0 -and ($hasEncoding -or $hasDynamic -or $hasDownloader))
    ) {
        'Medium'
    }
    elseif ($score -ge 2 -or $keywordHits.Count -ge 2 -or $blobHits.Count -gt 0 -or $hasTemp -or $hasConstruction -or $hasKeywords) {
        'Info'
    }
    else {
        return $null
    }

    $type = if ($File.Name -eq 'package.json' -and $scriptContext.Keys.Count -gt 0) {
        'ObfuscationLoaderLifecycle'
    }
    elseif ($severity -eq 'Info') {
        'ObfuscationIndicator'
    }
    else {
        'ObfuscationStagedLoader'
    }

    $indicatorParts = New-Object 'System.Collections.Generic.List[string]'
    if ($hasEncoding) { $indicatorParts.Add('encoded or packed content') }
    if ($hasDynamic) { $indicatorParts.Add('dynamic execution') }
    if ($hasDownloader) { $indicatorParts.Add('network fetch') }
    if ($hasHidden) { $indicatorParts.Add('hidden launch') }
    if ($hasTemp) { $indicatorParts.Add('temp staging') }
    if ($hasConstruction) { $indicatorParts.Add('rebuilt commands or addresses') }
    if ($hasKeywords) { $indicatorParts.Add('loader wording') }

    $evidenceParts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($entry in @(
        @{ Prefix = 'Encoded'; Value = (Get-HitLabels -Hits @($encodedHits + $blobHits)) },
        @{ Prefix = 'Execution'; Value = (Get-HitLabels -Hits $dynamicHits) },
        @{ Prefix = 'Downloader'; Value = (Get-HitLabels -Hits $downloaderHits) },
        @{ Prefix = 'Hidden'; Value = (Get-HitLabels -Hits $hiddenHits) },
        @{ Prefix = 'Staging'; Value = (Get-HitLabels -Hits $tempHits) },
        @{ Prefix = 'Construction'; Value = (Get-HitLabels -Hits $constructionHits) },
        @{ Prefix = 'Keywords'; Value = (Get-HitLabels -Hits $keywordHits) }
    )) {
        if (-not [string]::IsNullOrWhiteSpace($entry.Value)) {
            $evidenceParts.Add("$($entry.Prefix): $($entry.Value)")
        }
    }

    if ($scriptContext.Keys.Count -gt 0) {
        $evidenceParts.Add("Scripts: $($scriptContext.Summary)")
    }

    Write-DebugLog "Analyzed $($File.FullName) with score $score"

    [pscustomobject]@{
        Severity       = $severity
        Type           = $type
        Path           = $File.FullName
        PackageName    = $PackageName
        Version        = $PackageVersion
        Indicator      = "Obfuscation/staged-loader heuristic score $score - $((($indicatorParts | Select-Object -Unique) -join ', '))"
        Evidence       = ($evidenceParts -join ' | ')
        Recommendation = Get-Recommendation -Severity $severity
    }
}

$results = New-Object 'System.Collections.Generic.List[object]'
$identity = Get-ProjectIdentity -FolderPath $ScanPath

try {
    $files = Get-ChildItem -LiteralPath $ScanPath -File -Force -ErrorAction Stop | Where-Object { Test-IsTargetFile -File $_ }
}
catch {
    $files = @()
}

foreach ($file in $files) {
    $analysis = Analyze-File -File $file -PackageName $identity.Name -PackageVersion $identity.Version
    if ($analysis) {
        Add-Finding -List $results -Severity $analysis.Severity -Type $analysis.Type -Path $analysis.Path -PackageName $analysis.PackageName -Version $analysis.Version -Indicator $analysis.Indicator -Evidence $analysis.Evidence -Recommendation $analysis.Recommendation
    }
}

$results