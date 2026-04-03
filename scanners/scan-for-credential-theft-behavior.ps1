# © 2026 Sooke Software — Ted Neustaedter.
# Licensed under the GNU General Public License, version 3 or later.
#
# scan-for-credential-theft-behavior.ps1 — scans a single folder
# (non-recursive) for local heuristic indicators of credential collection,
# token harvesting, secret packaging, and likely exfiltration behaviour.

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
    '.env.development',
    '.pypirc',
    '.netrc',
    '.git-credentials',
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

$SensitivePathRules = @(
    @{ Pattern = '(?:^|[^a-z0-9_])(?:~|\$home|\$\{?home\}?|%userprofile%)[/\\]\.npmrc(?:$|[^a-z0-9_])|(?:^|[^a-z0-9_])\.npmrc(?:$|[^a-z0-9_])'; Label = 'npm credential file path'; Weight = 2 },
    @{ Pattern = '(?:^|[^a-z0-9_])(?:~|\$home|\$\{?home\}?|%userprofile%)[/\\]\.pypirc(?:$|[^a-z0-9_])|(?:^|[^a-z0-9_])\.pypirc(?:$|[^a-z0-9_])'; Label = 'Python publish credential path'; Weight = 2 },
    @{ Pattern = '(?:^|[^a-z0-9_])(?:~|\$home|\$\{?home\}?|%userprofile%)[/\\]\.netrc(?:$|[^a-z0-9_])|(?:^|[^a-z0-9_])\.netrc(?:$|[^a-z0-9_])'; Label = 'netrc credential path'; Weight = 2 },
    @{ Pattern = '(?:^|[^a-z0-9_])(?:~|\$home|\$\{?home\}?|%userprofile%)[/\\]\.git-credentials(?:$|[^a-z0-9_])|(?:^|[^a-z0-9_])\.git-credentials(?:$|[^a-z0-9_])'; Label = 'git credential store path'; Weight = 2 },
    @{ Pattern = '(?:~|\$home|\$\{?home\}?|%userprofile%)[/\\]\.ssh(?:[/\\]|$)|authorized_keys|known_hosts|id_rsa|id_ed25519'; Label = 'SSH credential store path'; Weight = 2 },
    @{ Pattern = '(?:~|\$home|\$\{?home\}?|%userprofile%)[/\\]\.aws(?:[/\\](?:credentials|config))?'; Label = 'AWS credential store path'; Weight = 2 },
    @{ Pattern = '(?:~|\$home|\$\{?home\}?|%userprofile%)[/\\]\.azure(?:[/\\]|$)|%appdata%[/\\]azure'; Label = 'Azure credential store path'; Weight = 2 },
    @{ Pattern = '(?:~|\$home|\$\{?home\}?|%userprofile%)[/\\]\.config[/\\]gcloud(?:[/\\]|$)|google[/\\]cloud'; Label = 'GCP credential store path'; Weight = 2 },
    @{ Pattern = '%appdata%[/\\]code[/\\]user[/\\]globalstorage'; Label = 'VS Code global storage path'; Weight = 2 },
    @{ Pattern = '(?:^|[^a-z0-9_])(?:kubeconfig|\.kube[/\\]config)(?:$|[^a-z0-9_])'; Label = 'Kubernetes credential path'; Weight = 2 },
    @{ Pattern = '(?:~|\$home|\$\{?home\}?|%userprofile%)[/\\]\.docker[/\\]config\.json'; Label = 'Docker credential config path'; Weight = 2 },
    @{ Pattern = 'login data|cookies|local state|google[/\\]chrome[/\\]user data|chromium[/\\]user data|firefox[/\\]profiles'; Label = 'browser secret storage path'; Weight = 2 }
)

$SecretEnvRules = @(
    @{ Pattern = '(?<![a-z0-9_])(github_token|gh_token|npm_token|node_auth_token|aws_access_key_id|aws_secret_access_key|aws_session_token|azure_client_secret|azure_tenant_id|google_application_credentials|pip_index_url|pip_extra_index_url|twine_username|twine_password|vss_nuget_external_feed_endpoints|ci_job_token|docker_auth_config|kubeconfig|ssh_auth_sock)(?![a-z0-9_])'; Label = 'well-known secret environment variable'; Weight = 1 },
    @{ Pattern = '(?<![a-z0-9_])(jfrog_[a-z0-9_]+|artifactory_[a-z0-9_]+|gcp_[a-z0-9_]+)(?![a-z0-9_])'; Label = 'package or cloud secret environment prefix'; Weight = 1 }
)

$SecretReadRules = @(
    @{ Pattern = 'get-content|readalltext|file\.readalltext|fs\.readfile(?:sync)?|os\.readfile|open\s*\([^\)]*\)\.read'; Label = 'direct file read primitive'; Weight = 2 },
    @{ Pattern = 'cat\s+[^\r\n]*(?:\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.ssh|\.aws|kubeconfig)|type\s+[^\r\n]*(?:\.npmrc|\.pypirc|\.netrc|\.git-credentials|\.ssh|\.aws|kubeconfig)'; Label = 'shell read of likely secret store'; Weight = 2 },
    @{ Pattern = 'glob|find|findfirstfile|get-childitem|readdir|enumeratefiles|walkdir|scandir'; Label = 'filesystem enumeration primitive'; Weight = 1 }
)

$EnvAccessRules = @(
    @{ Pattern = 'process\.env|os\.environ|getenv\s*\(|\[environment\]::getenvironmentvariable|printenv|env\s*\|\s*grep|set\s*\|\s*findstr'; Label = 'environment secret enumeration'; Weight = 2 }
)

$PackagingRules = @(
    @{ Pattern = 'copy-item|copyfile|copy\s+[^\r\n]*(?:\.ssh|\.aws|\.npmrc|\.pypirc|\.netrc|\.git-credentials|kubeconfig)|cp\s+[^\r\n]*(?:\.ssh|\.aws|\.npmrc|\.pypirc|\.netrc|\.git-credentials|kubeconfig)'; Label = 'copying likely secret material'; Weight = 2 },
    @{ Pattern = 'compress-archive|tar\s+-|zip\s+-|7z\s+a|archive'; Label = 'archiving or compressing data'; Weight = 2 },
    @{ Pattern = 'to' + 'base' + '64string|from' + 'base' + '64string|base' + '64'; Label = 'encoding likely secret data'; Weight = 2 }
)

$OutboundRules = @(
    @{ Pattern = '\bcurl\b|\bwget\b|requests\.(?:post|put)\s*\(|axios\.(?:post|put)\s*\(|fetch\s*\('; Label = 'HTTP upload or outbound request primitive'; Weight = 3 },
    @{ Pattern = 'invoke-web' + 'request|invoke-rest' + 'method'; Label = 'PowerShell outbound request primitive'; Weight = 3 },
    @{ Pattern = '\bscp\b|\bsftp\b|\bftp\b|upload'; Label = 'file transfer primitive'; Weight = 2 },
    @{ Pattern = 'disc' + 'ord\.com/api/web' + 'hooks|web' + 'hook\.site|request' + 'bin|api\.tele' + 'gram\.org/bot'; Label = 'webhook or callback endpoint'; Weight = 3 },
    @{ Pattern = 'https?://\d{1,3}(?:\.\d{1,3}){3}'; Label = 'raw IP callback URL'; Weight = 3 }
)

$ExecutionRules = @(
    @{ Pattern = 'power' + 'shell\s+-e(?:n|nc)\b|pw' + 'sh\s+-e(?:n|nc)\b'; Label = 'encoded shell execution'; Weight = 1 },
    @{ Pattern = 'node\s+-e\b|python\s+-c\b|bash\s+-c\b|sh\s+-c\b|cmd\s*/c\b'; Label = 'inline shell execution'; Weight = 1 },
    @{ Pattern = 'start' + '-process|subprocess|child' + '_' + 'process|sp' + 'awn\s*\(|ex' + 'ec\s*\(|ev' + 'al\s*\(|at' + 'ob\s*\('; Label = 'script execution helper'; Weight = 1 },
    @{ Pattern = '-windowstyle\s+hidden|-w\s+hidden'; Label = 'hidden shell execution'; Weight = 1 }
)

$TheftKeywordRules = @(
    @{ Pattern = 'steal|credential\s+dump|secrets?\s+dump|token\s+dump|harvest|exfil|gather\s+credentials|upload\s+secrets|export\s+env'; Label = 'explicit theft-oriented wording'; Weight = 1 }
)

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
        ($_ -notmatch '^\s*\$[A-Za-z0-9_]+\s*=\s*@\($') -and
        ($_ -notmatch '^\s*\$[A-Za-z0-9_]+\s*=\s*\@\($') -and
        ($_ -notmatch '^\s*\$[A-Za-z0-9_]+\s*=\s*\@\($')
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

    @{
        Name    = [string]($json.name ?? '')
        Version = [string]($json.version ?? '')
    }
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
            Get-RuleHits -Text $scriptValue -Rules $SensitivePathRules
            Get-RuleHits -Text $scriptValue -Rules $SecretEnvRules
            Get-RuleHits -Text $scriptValue -Rules $SecretReadRules
            Get-RuleHits -Text $scriptValue -Rules $EnvAccessRules
            Get-RuleHits -Text $scriptValue -Rules $PackagingRules
            Get-RuleHits -Text $scriptValue -Rules $OutboundRules
            Get-RuleHits -Text $scriptValue -Rules $ExecutionRules
            Get-RuleHits -Text $scriptValue -Rules $TheftKeywordRules
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
            'Investigate immediately. This file combines secret access indicators with packaging or outbound behaviour consistent with credential theft.'
        }
        'Medium' {
            'Review this file carefully. The combined heuristics suggest suspicious secret collection or token harvesting behaviour.'
        }
        default {
            'Review in context. This may be benign configuration handling, but it references sensitive secrets or credential stores.'
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

    $sensitiveHits = @(Get-RuleHits -Text $scanText -Rules $SensitivePathRules)
    $secretEnvHits = @(Get-RuleHits -Text $scanText -Rules $SecretEnvRules)
    $secretReadHits = @(Get-RuleHits -Text $scanText -Rules $SecretReadRules)
    $envAccessHits = @(Get-RuleHits -Text $scanText -Rules $EnvAccessRules)
    $packagingHits = @(Get-RuleHits -Text $scanText -Rules $PackagingRules)
    $outboundHits = @(Get-RuleHits -Text $scanText -Rules $OutboundRules)
    $executionHits = @(Get-RuleHits -Text $scanText -Rules $ExecutionRules)
    $keywordHits = @(Get-RuleHits -Text $scanText -Rules $TheftKeywordRules)

    $hasSecretSource = ($sensitiveHits.Count -gt 0) -or ($secretEnvHits.Count -gt 0)
    $hasCollectionSignal = ($secretReadHits.Count -gt 0) -or ($envAccessHits.Count -gt 0) -or ($packagingHits.Count -gt 0)
    $hasTheftSignal = ($keywordHits.Count -gt 0) -and (($hasCollectionSignal) -or ($outboundHits.Count -gt 0))

    if (-not $hasSecretSource -and -not $hasTheftSignal) {
        return $null
    }

    $score = 0
    $score += Get-HitWeight -Hits $sensitiveHits
    $score += Get-HitWeight -Hits $secretEnvHits
    $score += Get-HitWeight -Hits $secretReadHits
    $score += Get-HitWeight -Hits $envAccessHits
    $score += Get-HitWeight -Hits $packagingHits
    $score += Get-HitWeight -Hits $outboundHits
    $score += Get-HitWeight -Hits $executionHits
    $score += Get-HitWeight -Hits $keywordHits

    if ($sensitiveHits.Count -ge 2) { $score += 2 }
    if ($secretEnvHits.Count -ge 2) { $score += 1 }
    if (($sensitiveHits.Count -gt 0) -and ($secretReadHits.Count -gt 0)) { $score += 2 }
    if (($secretEnvHits.Count -gt 0) -and ($envAccessHits.Count -gt 0)) { $score += 2 }
    if (($packagingHits.Count -gt 0) -and $hasSecretSource) { $score += 3 }
    if (($executionHits.Count -gt 0) -and (($outboundHits.Count -gt 0) -or $hasCollectionSignal)) { $score += 2 }

    $scriptContext = @{ Keys = @(); Summary = '' }
    if ($File.Name -eq 'package.json') {
        $scriptContext = Get-PackageScriptContext -PackageJsonPath $File.FullName
        if ($scriptContext.Keys.Count -gt 0 -and $hasSecretSource) {
            $score += 2
        }
    }
    elseif ($File.Name -in @('Dockerfile', 'Makefile', 'Jenkinsfile')) {
        if ($hasSecretSource -and (($outboundHits.Count -gt 0) -or $hasCollectionSignal)) {
            $score += 2
        }
    }

    $strongExfil = ($outboundHits.Count -gt 0) -and (
        (($sensitiveHits.Count -gt 0) -and ($secretReadHits.Count -gt 0)) -or
        (($secretEnvHits.Count -gt 0) -and ($envAccessHits.Count -gt 0)) -or
        (($packagingHits.Count -gt 0) -and $hasSecretSource)
    )

    $highConfidence = $strongExfil -or (
        ($outboundHits.Count -gt 0) -and
        $hasSecretSource -and
        $hasCollectionSignal -and
        (($executionHits.Count -gt 0) -or ($keywordHits.Count -gt 0))
    ) -or (
        ($packagingHits.Count -gt 0) -and
        ($outboundHits.Count -gt 0) -and
        $hasSecretSource
    )

    $severity = if ($highConfidence) {
        'HIGH'
    }
    elseif ($score -ge 4) {
        'Medium'
    }
    else {
        'Info'
    }

    $type = if ($File.Name -eq 'package.json' -and $scriptContext.Keys.Count -gt 0) {
        'CredentialTheftLifecycle'
    }
    elseif ($severity -eq 'Info') {
        'CredentialAccessIndicator'
    }
    else {
        'CredentialTheftBehavior'
    }

    $indicatorParts = New-Object 'System.Collections.Generic.List[string]'
    if ($sensitiveHits.Count -gt 0) { $indicatorParts.Add('secret-store references') }
    if ($secretEnvHits.Count -gt 0) { $indicatorParts.Add('secret env names') }
    if (($secretReadHits.Count + $envAccessHits.Count) -gt 0) { $indicatorParts.Add('credential access logic') }
    if ($packagingHits.Count -gt 0) { $indicatorParts.Add('packaging or encoding') }
    if ($outboundHits.Count -gt 0) { $indicatorParts.Add('outbound transfer') }
    if ($executionHits.Count -gt 0) { $indicatorParts.Add('script execution') }
    if ($keywordHits.Count -gt 0) { $indicatorParts.Add('theft wording') }

    $evidenceParts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($entry in @(
        @{ Prefix = 'Paths'; Value = (Get-HitLabels -Hits $sensitiveHits) },
        @{ Prefix = 'Env'; Value = (Get-HitLabels -Hits $secretEnvHits) },
        @{ Prefix = 'Access'; Value = (Get-HitLabels -Hits @($secretReadHits + $envAccessHits)) },
        @{ Prefix = 'Packaging'; Value = (Get-HitLabels -Hits $packagingHits) },
        @{ Prefix = 'Outbound'; Value = (Get-HitLabels -Hits $outboundHits) },
        @{ Prefix = 'Execution'; Value = (Get-HitLabels -Hits $executionHits) },
        @{ Prefix = 'Keywords'; Value = (Get-HitLabels -Hits $keywordHits) }
    )) {
        if (-not [string]::IsNullOrWhiteSpace($entry.Value)) {
            $evidenceParts.Add("$($entry.Prefix): $($entry.Value)")
        }
    }

    if ($scriptContext.Keys.Count -gt 0) {
        $evidenceParts.Add("Scripts: $($scriptContext.Summary)")
    }

    [pscustomobject]@{
        Severity       = $severity
        Type           = $type
        Path           = $File.FullName
        PackageName    = $PackageName
        Version        = $PackageVersion
        Indicator      = "Credential theft heuristic score $score — $((($indicatorParts | Select-Object -Unique) -join ', '))"
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