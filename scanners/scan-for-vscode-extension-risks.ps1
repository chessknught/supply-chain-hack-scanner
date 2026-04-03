# © 2026 Sooke Software — Ted Neustaedter.
# Licensed under the GNU General Public License, version 3 or later.
#
# scan-for-vscode-extension-risks.ps1 — scans a single folder
# (non-recursive) for local heuristic indicators of risky VS Code / Open VSX
# extension manifest settings, lifecycle scripts, workspace access, secret
# access, outbound traffic, and persistence-adjacent behaviour.

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
    'extension.js',
    'extension.ts',
    'main.js',
    'main.ts',
    'README.md',
    'CHANGELOG.md',
    'LICENSE',
    '.vscodeignore',
    '.npmrc',
    '.env',
    '.env.local'
)

$TargetExtensions = @(
    '.js', '.cjs', '.mjs', '.ts',
    '.json', '.yml', '.yaml',
    '.ps1', '.sh'
)

$ManifestIndicatorKeys = @(
    'main',
    'activationEvents',
    'contributes',
    'publisher',
    'displayName',
    'categories',
    'extensionKind',
    'browser',
    'capabilities',
    'enabledApiProposals',
    'extensionDependencies',
    'extensionPack'
)

$LifecycleScriptKeys = @(
    'preinstall', 'install', 'postinstall', 'prepare',
    'prepublishOnly', 'vscode:prepublish', 'compile', 'watch', 'package'
)

$InvokeWebRequestFragment = 'invoke-web' + 'request'
$InvokeRestMethodFragment = 'invoke-rest' + 'method'
$InvokeExpressionFragment = 'invoke-exp' + 'ression|(^|[^a-z])i' + 'ex([^a-z]|$)'
$PowerShellFragment = 'power' + 'shell'
$PwshFragment = 'pw' + 'sh'
$BitsAdminFragment = 'bits' + 'admin'
$MshtaFragment = 'ms' + 'hta'
$RunDllFragment = 'run' + 'dll32'
$RegsvrFragment = 'reg' + 'svr32'
$CertUtilFragment = 'cert' + 'util'
$StartProcessFragment = 'start' + '-process'
$FromBase64Fragment = 'from' + 'base' + '64string'
$Base64Fragment = 'base' + '64'
$EvalFragment = 'ev' + 'al'
$AtobFragment = 'at' + 'ob'
$FunctionFragment = 'fu' + 'nction'
$ChildProcessFragment = 'child' + '_' + 'process'
$SpawnFragment = 'sp' + 'awn'
$ExecFragment = 'ex' + 'ec'
$DiscordWebhookFragment = 'disc' + 'ord\.com/api/web' + 'hooks'
$TelegramBotFragment = 'api\.tele' + 'gram\.org/bot'
$WebhookSiteFragment = 'web' + 'hook\.site'
$RequestBinFragment = 'request' + 'bin'
$GlobalStorageFragment = 'global' + 'storage'
$WorkspaceStorageFragment = 'workspace' + 'storage'

$LifecycleScriptRules = @(
    @{ Pattern = '\bcurl\b|\bwget\b'; Label = 'shell downloader primitive'; Weight = 2 },
    @{ Pattern = $InvokeWebRequestFragment + '|' + $InvokeRestMethodFragment + '|(^|[^a-z])iwr([^a-z]|$)'; Label = 'PowerShell downloader primitive'; Weight = 2 },
    @{ Pattern = $CertUtilFragment + '|' + $BitsAdminFragment + '|' + $MshtaFragment + '|' + $RunDllFragment + '|' + $RegsvrFragment; Label = 'system execution utility'; Weight = 3 },
    @{ Pattern = $PowerShellFragment + '\s+-e(?:n|nc)\b|' + $PwshFragment + '\s+-e(?:n|nc)\b'; Label = 'encoded shell launch'; Weight = 3 },
    @{ Pattern = 'node\s+-e\b|bash\s+-c\b|sh\s+-c\b|cmd\s*/c\b'; Label = 'inline command launch'; Weight = 2 },
    @{ Pattern = $EvalFragment + '\s*\(|' + $FunctionFragment + '\s*\(|' + $ExecFragment + '\s*\(|' + $SpawnFragment + '\s*\(|' + $ChildProcessFragment; Label = 'dynamic execution helper'; Weight = 3 },
    @{ Pattern = '\bcurl\b[^\r\n|]{0,200}\|\s*(?:ba|z)?sh\b|\bwget\b[^\r\n|]{0,200}\|\s*(?:ba|z)?sh\b'; Label = 'remote script piped to shell'; Weight = 4 },
    @{ Pattern = $InvokeWebRequestFragment + '[^\r\n|]{0,200}\|\s*(?:' + $InvokeExpressionFragment + ')'; Label = 'download piped into expression'; Weight = 4 },
    @{ Pattern = $DiscordWebhookFragment + '|' + $TelegramBotFragment + '|' + $WebhookSiteFragment + '|' + $RequestBinFragment; Label = 'webhook or callback endpoint'; Weight = 3 },
    @{ Pattern = 'download\s+payload|execute\s+silently|update\s+silently'; Label = 'stealth update wording'; Weight = 2 }
)

$NetworkRules = @(
    @{ Pattern = $DiscordWebhookFragment + '|' + $TelegramBotFragment + '|' + $WebhookSiteFragment + '|' + $RequestBinFragment + '|ngrok|paste' + 'bin|paste\.ee|ghost' + 'bin'; Label = 'suspicious outbound endpoint'; Weight = 3 },
    @{ Pattern = '\bcurl\b|\bwget\b|axios\.(?:get|post)\s*\(|fetch\s*\(|requests\.(?:get|post)\s*\('; Label = 'outbound request primitive'; Weight = 2 },
    @{ Pattern = $InvokeWebRequestFragment + '|' + $InvokeRestMethodFragment + '|(^|[^a-z])iwr([^a-z]|$)'; Label = 'PowerShell outbound request'; Weight = 2 },
    @{ Pattern = 'https?://\d{1,3}(?:\.\d{1,3}){3}'; Label = 'raw IP URL'; Weight = 3 },
    @{ Pattern = 'download(string|file)?|webclient\.download|urlretrieve'; Label = 'payload download helper'; Weight = 2 }
)

$SecretPathRules = @(
    @{ Pattern = '(?:~|%userprofile%|\$home|\$env:homepath|os\.homedir\s*\(\))[/\\]\.ssh(?:[/\\]|$)|authorized_keys|known_hosts|id_rsa|id_ed25519'; Label = 'SSH material access'; Weight = 3 },
    @{ Pattern = '\.npmrc|\.git-credentials|\.aws(?:[/\\]|$)|\.azure(?:[/\\]|$)|\.config[/\\]gcloud'; Label = 'package or cloud secret file access'; Weight = 2 },
    @{ Pattern = 'login data|cookies|local state|chrome[/\\]user data|firefox[/\\]profiles'; Label = 'browser profile access'; Weight = 3 },
    @{ Pattern = 'appdata|%appdata%|' + $GlobalStorageFragment + '|' + $WorkspaceStorageFragment + '|user[/\\]settings\.json'; Label = 'VS Code or profile storage access'; Weight = 2 },
    @{ Pattern = 'globalstorage|workspacestorage|storage\.json'; Label = 'extension storage inspection'; Weight = 2 }
)

$SecretEnvRules = @(
    @{ Pattern = '(^|[^a-z0-9_])(github_token|npm_token|node_auth_token|ssh_auth_sock|vscode_git_askpass_[a-z0-9_]*)([^a-z0-9_]|$)'; Label = 'developer token variable'; Weight = 2 },
    @{ Pattern = '(^|[^a-z0-9_])(aws_[a-z0-9_]+|azure_[a-z0-9_]+|google_[a-z0-9_]+)([^a-z0-9_]|$)'; Label = 'cloud secret variable'; Weight = 2 },
    @{ Pattern = 'process\.env|\[environment\]::getenvironmentvariable|getenv\s*\('; Label = 'environment enumeration primitive'; Weight = 1 }
)

$VscodeApiRules = @(
    @{ Pattern = 'vscode\.workspace\.findfiles'; Label = 'workspace file enumeration API'; Weight = 2 },
    @{ Pattern = 'vscode\.workspace\.fs'; Label = 'workspace filesystem API'; Weight = 2 },
    @{ Pattern = 'vscode\.commands\.executecommand'; Label = 'command execution API'; Weight = 2 },
    @{ Pattern = 'vscode\.window\.createterminal|terminal\.sendtext'; Label = 'terminal automation API'; Weight = 3 },
    @{ Pattern = 'extensions\.(?:all|getextension)|installextension'; Label = 'extension manipulation API'; Weight = 2 },
    @{ Pattern = 'getconfiguration\s*\(\)\.update|settings\.json'; Label = 'settings modification logic'; Weight = 2 },
    @{ Pattern = 'os\.homedir\s*\(|appdata|globalstorage|workspacestorage'; Label = 'user-profile storage access'; Weight = 1 }
)

$PersistenceRules = @(
    @{ Pattern = 'schtasks|crontab|launchctl|startup|runonce|registry'; Label = 'persistence primitive'; Weight = 3 },
    @{ Pattern = 'temp|tmp|appdata[/\\]local[/\\]temp|%temp%'; Label = 'temporary payload staging'; Weight = 1 },
    @{ Pattern = $StartProcessFragment + '|subprocess|process\.start'; Label = 'process launch helper'; Weight = 2 },
    @{ Pattern = 'auto-?update|download\s+payload|execute\s+silently|update\s+silently'; Label = 'silent update wording'; Weight = 2 },
    @{ Pattern = 'writefile(?:sync)?\s*\(|set-content|out-file|copy-item|copyfile'; Label = 'file write primitive'; Weight = 2 }
)

$PackagingRules = @(
    @{ Pattern = '[A-Za-z0-9+/=]{180,}'; Label = 'large encoded blob'; Weight = 2 },
    @{ Pattern = '(?:\\x[0-9A-Fa-f]{2}){24,}|(?:\\u[0-9A-Fa-f]{4}){12,}'; Label = 'escaped byte blob'; Weight = 2 },
    @{ Pattern = '\.(?:exe|dll|so|dylib|bin)'; Label = 'bundled executable reference'; Weight = 2 },
    @{ Pattern = '(?:^|[/\\])(src|test|tests|docs|\.github)(?:[/\\*]|$)|\.map'; Label = 'review-surface exclusion'; Weight = 1 },
    @{ Pattern = 'minified|bundle|packed'; Label = 'bundled artifact wording'; Weight = 1 }
)

$ObfuscationRules = @(
    @{ Pattern = $FromBase64Fragment + '|\b' + $Base64Fragment + '\b'; Label = 'base64 helper'; Weight = 2 },
    @{ Pattern = $AtobFragment + '\s*\('; Label = 'browser decode helper'; Weight = 2 },
    @{ Pattern = $EvalFragment + '\s*\(|' + $FunctionFragment + '\s*\('; Label = 'runtime evaluation'; Weight = 2 },
    @{ Pattern = $ChildProcessFragment + '|' + $SpawnFragment + '\s*\(|' + $ExecFragment + '\s*\('; Label = 'process execution helper'; Weight = 2 },
    @{ Pattern = 'string\.fromcharcode|charcodeat|join\s*\(|replace\s*\([^\)]{0,120}(?:http|cmd|exe|dll|sh)'; Label = 'string reconstruction'; Weight = 2 },
    @{ Pattern = '(?:["''][^"''\r\n]{1,10}["'']\s*(?:\+\s*["''][^"''\r\n]{1,10}["'']\s*){5,})'; Label = 'fragmented string assembly'; Weight = 2 }
)

$KeywordRules = @(
    @{ Pattern = 'webhook|exfil|stealth|hidden|loader|bootstrap|secret|credential'; Label = 'risky wording'; Weight = 1 },
    @{ Pattern = 'collect\s+env|' + $GlobalStorageFragment + '|' + $WorkspaceStorageFragment; Label = 'collection wording'; Weight = 1 }
)

$DependencyKeywordRules = @(
    @{ Pattern = 'loader|bootstrap|stealth|webhook|credential|token|update'; Label = 'suspicious dependency naming'; Weight = 1 }
)

function Write-DebugLog {
    param([string]$Message)

    if ($VerbosityLevel -gt 0) {
        Write-Verbose $Message
    }
}

function Test-JsonProperty {
    param(
        $Object,
        [string]$Name
    )

    if ($null -eq $Object) {
        return $false
    }

    $Object.PSObject.Properties.Name -contains $Name
}

function Get-PropertyValue {
    param(
        $Object,
        [string]$Name
    )

    if (-not (Test-JsonProperty -Object $Object -Name $Name)) {
        return $null
    }

    $Object.$Name
}

function Get-ArrayValues {
    param($Value)

    if ($null -eq $Value) {
        return @()
    }

    if ($Value -is [System.Array]) {
        return @($Value | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }

    if ($Value -is [System.Collections.IEnumerable] -and -not ($Value -is [string])) {
        return @($Value | ForEach-Object { [string]$_ } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    }

    if ([string]::IsNullOrWhiteSpace([string]$Value)) {
        return @()
    }

    @([string]$Value)
}

function Get-CollectionCount {
    param($Value)

    if ($null -eq $Value) {
        return 0
    }

    if ($Value -is [string]) {
        return [int](-not [string]::IsNullOrWhiteSpace($Value))
    }

    if ($Value -is [System.Collections.IDictionary]) {
        return $Value.Keys.Count
    }

    if ($Value -is [System.Array]) {
        return $Value.Count
    }

    if ($Value -is [System.Collections.IEnumerable]) {
        return @($Value).Count
    }

    1
}

function New-Hit {
    param(
        [string]$Label,
        [int]$Weight
    )

    [pscustomobject]@{
        Label  = $Label
        Weight = $Weight
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
        ($_ -notmatch '^\s*\$[A-Za-z0-9_]+\s*=\s*@\(')
    }) -join "`n"
}

function Get-RuleHits {
    param(
        [string]$Text,
        [object[]]$Rules
    )

    $hits = New-Object 'System.Collections.Generic.List[object]'
    foreach ($rule in $Rules) {
        if ([regex]::IsMatch($Text, $rule.Pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
            $hits.Add((New-Hit -Label $rule.Label -Weight $rule.Weight))
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

function Get-ProjectIdentity {
    param([string]$FolderPath)

    $pkgPath = Join-Path $FolderPath 'package.json'
    $json = Get-JsonFile -Path $pkgPath
    if (-not $json) {
        return @{ Name = ''; Version = ''; Publisher = ''; DisplayName = '' }
    }

    @{
        Name        = [string](Get-PropertyValue -Object $json -Name 'name')
        Version     = [string](Get-PropertyValue -Object $json -Name 'version')
        Publisher   = [string](Get-PropertyValue -Object $json -Name 'publisher')
        DisplayName = [string](Get-PropertyValue -Object $json -Name 'displayName')
    }
}

function Test-IsTargetFile {
    param([System.IO.FileInfo]$File)

    if ($ExactTargetFiles -contains $File.Name) {
        return $true
    }

    $TargetExtensions -contains $File.Extension
}

function Get-ActivationInfo {
    param([string[]]$ActivationEvents)

    $hits = New-Object 'System.Collections.Generic.List[object]'
    foreach ($event in $ActivationEvents) {
        $normalized = $event.ToLowerInvariant()
        switch -Regex ($normalized) {
            '^\*$' {
                $hits.Add((New-Hit -Label 'wildcard activation' -Weight 3))
                continue
            }
            '^onstartupfinished$' {
                $hits.Add((New-Hit -Label 'startup activation' -Weight 2))
                continue
            }
            '^workspacecontains:\*\*' {
                $hits.Add((New-Hit -Label 'workspace-wide activation' -Weight 2))
                continue
            }
            '^onfilesystem:' {
                $hits.Add((New-Hit -Label 'filesystem activation' -Weight 1))
                continue
            }
            '^onview:' {
                $hits.Add((New-Hit -Label 'view activation' -Weight 1))
                continue
            }
            '^oncommand:' {
                $hits.Add((New-Hit -Label 'command activation' -Weight 1))
                continue
            }
        }
    }

    if ($ActivationEvents.Count -ge 6) {
        $hits.Add((New-Hit -Label 'many activation events' -Weight 2))
    }

    [pscustomobject]@{
        Events             = $ActivationEvents
        Hits               = $hits.ToArray()
        HasBroadActivation = @($hits | Where-Object { $_.Label -in @('wildcard activation', 'startup activation', 'workspace-wide activation', 'many activation events') }).Count -gt 0
    }
}

function Get-ManifestCapabilityHits {
    param($PackageJson)

    $hits = New-Object 'System.Collections.Generic.List[object]'

    if (-not $PackageJson) {
        return $hits.ToArray()
    }

    if ((Get-CollectionCount -Value (Get-PropertyValue -Object $PackageJson -Name 'enabledApiProposals')) -gt 0) {
        $hits.Add((New-Hit -Label 'experimental API proposals' -Weight 3))
    }

    if ((Get-CollectionCount -Value (Get-PropertyValue -Object $PackageJson -Name 'extensionDependencies')) -gt 0) {
        $hits.Add((New-Hit -Label 'extension dependency chaining' -Weight 1))
    }

    if ((Get-CollectionCount -Value (Get-PropertyValue -Object $PackageJson -Name 'extensionPack')) -gt 0) {
        $hits.Add((New-Hit -Label 'extension pack fan-out' -Weight 1))
    }

    $extensionKindCount = Get-CollectionCount -Value (Get-PropertyValue -Object $PackageJson -Name 'extensionKind')
    if ($extensionKindCount -gt 1) {
        $hits.Add((New-Hit -Label 'multi-surface extension kind' -Weight 1))
    }

    if ((Get-CollectionCount -Value (Get-PropertyValue -Object $PackageJson -Name 'capabilities')) -gt 0) {
        $hits.Add((New-Hit -Label 'explicit capability block' -Weight 1))
    }

    $contributes = Get-PropertyValue -Object $PackageJson -Name 'contributes'
    if ($contributes) {
        $powerfulPoints = @('commands', 'debuggers', 'notebooks', 'taskDefinitions', 'scm', 'views', 'menus') | Where-Object {
            Test-JsonProperty -Object $contributes -Name $_
        }

        if ($powerfulPoints.Count -gt 0) {
            $hits.Add((New-Hit -Label 'powerful contribution points' -Weight 1))
        }
    }

    $hits.ToArray()
}

function Get-DependencyKeywordHits {
    param($PackageJson)

    if (-not $PackageJson) {
        return @()
    }

    $dependencyNames = New-Object 'System.Collections.Generic.List[string]'
    foreach ($propertyName in @('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies')) {
        $block = Get-PropertyValue -Object $PackageJson -Name $propertyName
        if (-not $block) {
            continue
        }

        foreach ($name in $block.PSObject.Properties.Name) {
            if (-not [string]::IsNullOrWhiteSpace($name)) {
                $dependencyNames.Add($name)
            }
        }
    }

    if ($dependencyNames.Count -eq 0) {
        return @()
    }

    Get-RuleHits -Text (($dependencyNames | Select-Object -Unique) -join "`n") -Rules $DependencyKeywordRules
}

function Get-ScriptHits {
    param([string]$Text)

    @(
        Get-RuleHits -Text $Text -Rules $LifecycleScriptRules
        Get-RuleHits -Text $Text -Rules $NetworkRules
        Get-RuleHits -Text $Text -Rules $SecretPathRules
        Get-RuleHits -Text $Text -Rules $SecretEnvRules
        Get-RuleHits -Text $Text -Rules $PersistenceRules
        Get-RuleHits -Text $Text -Rules $ObfuscationRules
        Get-RuleHits -Text $Text -Rules $KeywordRules
    )
}

function Get-LifecycleScriptContext {
    param($PackageJson)

    $matchedKeys = New-Object 'System.Collections.Generic.List[string]'
    $hits = New-Object 'System.Collections.Generic.List[object]'

    if (-not $PackageJson -or -not (Test-JsonProperty -Object $PackageJson -Name 'scripts')) {
        return @{ Keys = @(); Hits = @(); Summary = '' }
    }

    $scripts = $PackageJson.scripts
    foreach ($key in $LifecycleScriptKeys) {
        if ($scripts.PSObject.Properties.Name -notcontains $key) {
            continue
        }

        $scriptValue = [string]$scripts.$key
        if ([string]::IsNullOrWhiteSpace($scriptValue)) {
            continue
        }

        $scriptHits = @(Get-ScriptHits -Text $scriptValue)
        if ($scriptHits.Count -eq 0) {
            continue
        }

        $matchedKeys.Add($key)
        foreach ($hit in $scriptHits) {
            $hits.Add($hit)
        }
    }

    @{
        Keys    = $matchedKeys.ToArray()
        Hits    = $hits.ToArray()
        Summary = ($matchedKeys -join ', ')
    }
}

function Get-ExtensionManifestContext {
    param([string]$FolderPath)

    $pkgPath = Join-Path $FolderPath 'package.json'
    $pkgText = Get-FileText -Path $pkgPath
    $pkgJson = Get-JsonFile -Path $pkgPath
    $markers = New-Object 'System.Collections.Generic.List[string]'
    $activationEvents = @()

    if ($pkgJson) {
        $engines = Get-PropertyValue -Object $pkgJson -Name 'engines'
        if ($engines -and (Test-JsonProperty -Object $engines -Name 'vscode') -and -not [string]::IsNullOrWhiteSpace([string]$engines.vscode)) {
            $markers.Add('engines.vscode')
        }

        foreach ($key in $ManifestIndicatorKeys) {
            $value = Get-PropertyValue -Object $pkgJson -Name $key
            if ((Get-CollectionCount -Value $value) -gt 0) {
                $markers.Add($key)
            }
        }

        $activationEvents = @(Get-ArrayValues -Value (Get-PropertyValue -Object $pkgJson -Name 'activationEvents'))
    }
    elseif (-not [string]::IsNullOrWhiteSpace($pkgText)) {
        if ($pkgText -match '"engines"\s*:\s*\{[^\}]{0,300}"vscode"') {
            $markers.Add('engines.vscode')
        }

        foreach ($key in $ManifestIndicatorKeys) {
            if ($pkgText -match ('"' + [regex]::Escape($key) + '"\s*:')) {
                $markers.Add($key)
            }
        }
    }

    foreach ($entryFile in @('extension.js', 'extension.ts', 'main.js', 'main.ts')) {
        if (Test-Path -LiteralPath (Join-Path $FolderPath $entryFile) -PathType Leaf) {
            $markers.Add('entry file present')
            break
        }
    }

    $activationInfo = Get-ActivationInfo -ActivationEvents $activationEvents
    $uniqueMarkers = @($markers | Select-Object -Unique)
    $isExtension = ($uniqueMarkers.Count -ge 2) -or ($uniqueMarkers -contains 'engines.vscode') -or (($uniqueMarkers -contains 'activationEvents') -and ($uniqueMarkers -contains 'contributes'))

    [pscustomobject]@{
        IsExtension    = $isExtension
        PackageJson    = $pkgJson
        PackageText    = $pkgText
        Markers        = $uniqueMarkers
        ActivationInfo = $activationInfo
    }
}

function Get-Recommendation {
    param([string]$Severity)

    switch ($Severity) {
        'HIGH' {
            'Investigate immediately. This extension folder combines activation or extension APIs with behaviour consistent with secret access, outbound transfer, or staged execution.'
        }
        'Medium' {
            'Review closely. The local manifest or adjacent code shows extension capabilities combined with suspicious install, network, or workspace interaction patterns.'
        }
        default {
            'Review in context. This looks like an extension project with activation, capability, or workspace access patterns that warrant a manual check.'
        }
    }
}

function Get-EvidenceSummary {
    param(
        [hashtable[]]$Entries,
        [string]$ScriptSummary = ''
    )

    $parts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($entry in $Entries) {
        if (-not [string]::IsNullOrWhiteSpace($entry.Value)) {
            $parts.Add("$($entry.Prefix): $($entry.Value)")
        }
    }

    if (-not [string]::IsNullOrWhiteSpace($ScriptSummary)) {
        $parts.Add("Scripts: $ScriptSummary")
    }

    $parts -join ' | '
}

function Analyze-PackageManifest {
    param(
        [System.IO.FileInfo]$File,
        $Context,
        [hashtable]$Identity
    )

    if (-not $Context.IsExtension) {
        return $null
    }

    $capabilityHits = @(Get-ManifestCapabilityHits -PackageJson $Context.PackageJson)
    $dependencyHits = @(Get-DependencyKeywordHits -PackageJson $Context.PackageJson)
    $scriptContext = Get-LifecycleScriptContext -PackageJson $Context.PackageJson
    $keywordHits = @(Get-RuleHits -Text (Get-ScanText -Text $Context.PackageText) -Rules $KeywordRules)
    $activationHits = @($Context.ActivationInfo.Hits)

    if ($activationHits.Count -eq 0 -and $capabilityHits.Count -eq 0 -and $scriptContext.Hits.Count -eq 0 -and $dependencyHits.Count -eq 0 -and $keywordHits.Count -eq 0) {
        return $null
    }

    $score = 0
    $score += Get-HitWeight -Hits $activationHits
    $score += Get-HitWeight -Hits $capabilityHits
    $score += Get-HitWeight -Hits $scriptContext.Hits
    $score += Get-HitWeight -Hits $dependencyHits
    $score += Get-HitWeight -Hits $keywordHits

    if ($Context.ActivationInfo.HasBroadActivation -and $scriptContext.Hits.Count -gt 0) {
        $score += 3
    }
    if ($Context.ActivationInfo.HasBroadActivation -and $capabilityHits.Count -gt 0) {
        $score += 1
    }
    if ($scriptContext.Hits.Count -gt 0 -and $capabilityHits.Count -gt 0) {
        $score += 2
    }
    if ($scriptContext.Hits.Count -gt 0 -and $dependencyHits.Count -gt 0) {
        $score += 1
    }

    $highConfidence = $Context.ActivationInfo.HasBroadActivation -and ($scriptContext.Hits.Count -gt 0) -and ((Get-HitWeight -Hits $scriptContext.Hits) -ge 6)

    $severity = 'Info'
    if ($highConfidence -or $score -ge 10) {
        $severity = 'HIGH'
    }
    elseif ($score -ge 4) {
        $severity = 'Medium'
    }

    $indicatorParts = New-Object 'System.Collections.Generic.List[string]'
    $indicatorParts.Add('extension manifest signals')
    if ($activationHits.Count -gt 0) { $indicatorParts.Add('activation risk') }
    if ($scriptContext.Hits.Count -gt 0) { $indicatorParts.Add('lifecycle script abuse') }
    if ($capabilityHits.Count -gt 0) { $indicatorParts.Add('powerful capability use') }
    if ($dependencyHits.Count -gt 0) { $indicatorParts.Add('dependency naming signal') }

    $evidence = Get-EvidenceSummary -Entries @(
        @{ Prefix = 'Manifest'; Value = ($Context.Markers -join '; ') },
        @{ Prefix = 'Activation'; Value = (Get-HitLabels -Hits $activationHits) },
        @{ Prefix = 'Capabilities'; Value = (Get-HitLabels -Hits $capabilityHits) },
        @{ Prefix = 'Dependencies'; Value = (Get-HitLabels -Hits $dependencyHits) },
        @{ Prefix = 'Keywords'; Value = (Get-HitLabels -Hits $keywordHits) }
    ) -ScriptSummary $scriptContext.Summary

    [pscustomobject]@{
        Severity       = $severity
        Type           = if ($scriptContext.Hits.Count -gt 0) { 'VscodeExtensionLifecycleRisk' } else { 'VscodeExtensionManifestRisk' }
        Path           = $File.FullName
        PackageName    = $Identity.Name
        Version        = $Identity.Version
        Indicator      = "VS Code extension heuristic score $score — $((($indicatorParts | Select-Object -Unique) -join ', '))"
        Evidence       = $evidence
        Recommendation = Get-Recommendation -Severity $severity
    }
}

function Analyze-TextFile {
    param(
        [System.IO.FileInfo]$File,
        $Context,
        [hashtable]$Identity
    )

    $text = Get-FileText -Path $File.FullName
    if ([string]::IsNullOrWhiteSpace($text)) {
        return $null
    }

    $scanText = Get-ScanText -Text $text
    if ([string]::IsNullOrWhiteSpace($scanText)) {
        return $null
    }

    $looksLikeExtensionCode = ($scanText -match 'require\s*\(\s*["'']vscode["'']') -or ($scanText -match 'from\s+["'']vscode["'']') -or ($scanText -match 'vscode\.')
    if (-not $Context.IsExtension -and -not $looksLikeExtensionCode) {
        return $null
    }

    $networkHits = @(Get-RuleHits -Text $scanText -Rules $NetworkRules)
    $secretPathHits = @(Get-RuleHits -Text $scanText -Rules $SecretPathRules)
    $secretEnvHits = @(Get-RuleHits -Text $scanText -Rules $SecretEnvRules)
    $apiHits = @(Get-RuleHits -Text $scanText -Rules $VscodeApiRules)
    $persistenceHits = @(Get-RuleHits -Text $scanText -Rules $PersistenceRules)
    $packagingHits = @(Get-RuleHits -Text $scanText -Rules $PackagingRules)
    $obfuscationHits = @(Get-RuleHits -Text $scanText -Rules $ObfuscationRules)
    $keywordHits = @(Get-RuleHits -Text $scanText -Rules $KeywordRules)

    $secretCount = $secretPathHits.Count + $secretEnvHits.Count
    $relevantSignal = ($networkHits.Count -gt 0) -or ($secretCount -gt 0) -or ($apiHits.Count -ge 2) -or ($persistenceHits.Count -gt 0) -or ($packagingHits.Count -gt 0) -or ($obfuscationHits.Count -gt 0)
    if (-not $relevantSignal) {
        return $null
    }

    $score = 0
    $score += Get-HitWeight -Hits $networkHits
    $score += Get-HitWeight -Hits $secretPathHits
    $score += Get-HitWeight -Hits $secretEnvHits
    $score += Get-HitWeight -Hits $apiHits
    $score += Get-HitWeight -Hits $persistenceHits
    $score += Get-HitWeight -Hits $packagingHits
    $score += Get-HitWeight -Hits $obfuscationHits
    $score += Get-HitWeight -Hits $keywordHits

    if ($apiHits.Count -gt 0 -and $networkHits.Count -gt 0) { $score += 3 }
    if ($apiHits.Count -gt 0 -and $secretCount -gt 0) { $score += 3 }
    if ($networkHits.Count -gt 0 -and $secretCount -gt 0) { $score += 4 }
    if ($persistenceHits.Count -gt 0 -and (($networkHits.Count -gt 0) -or ($secretCount -gt 0))) { $score += 3 }
    if ($obfuscationHits.Count -gt 0 -and $networkHits.Count -gt 0) { $score += 2 }
    if ($Context.ActivationInfo.HasBroadActivation -and (($apiHits.Count -gt 0) -or ($obfuscationHits.Count -gt 0))) { $score += 2 }
    if ($packagingHits.Count -gt 0 -and (($networkHits.Count -gt 0) -or ($obfuscationHits.Count -gt 0))) { $score += 2 }

    $highConfidence = (($networkHits.Count -gt 0) -and ($secretCount -gt 0) -and ($apiHits.Count -gt 0)) -or
        (($Context.ActivationInfo.HasBroadActivation) -and ($networkHits.Count -gt 0) -and ($obfuscationHits.Count -gt 0)) -or
        (($persistenceHits.Count -gt 0) -and ($networkHits.Count -gt 0) -and (($secretCount -gt 0) -or ($apiHits.Count -gt 0)))

    $severity = 'Info'
    if ($highConfidence -or $score -ge 10) {
        $severity = 'HIGH'
    }
    elseif ($score -ge 5) {
        $severity = 'Medium'
    }

    $indicatorParts = New-Object 'System.Collections.Generic.List[string]'
    if ($apiHits.Count -gt 0) { $indicatorParts.Add('extension API access') }
    if ($networkHits.Count -gt 0) { $indicatorParts.Add('outbound logic') }
    if ($secretCount -gt 0) { $indicatorParts.Add('secret access') }
    if ($persistenceHits.Count -gt 0) { $indicatorParts.Add('persistence or profile writes') }
    if ($obfuscationHits.Count -gt 0) { $indicatorParts.Add('obfuscation or staged execution') }
    if ($packagingHits.Count -gt 0) { $indicatorParts.Add('packaging signal') }

    $type = 'VscodeExtensionRiskIndicator'
    if ($networkHits.Count -gt 0 -and $secretCount -gt 0) {
        $type = 'VscodeExtensionCredentialRisk'
    }
    elseif ($persistenceHits.Count -gt 0) {
        $type = 'VscodeExtensionPersistenceRisk'
    }
    elseif ($apiHits.Count -gt 0 -and $networkHits.Count -gt 0) {
        $type = 'VscodeExtensionWorkspaceRisk'
    }
    elseif ($packagingHits.Count -gt 0) {
        $type = 'VscodeExtensionPackagingRisk'
    }
    elseif ($apiHits.Count -gt 0) {
        $type = 'VscodeExtensionApiRisk'
    }

    $evidence = Get-EvidenceSummary -Entries @(
        @{ Prefix = 'Activation'; Value = if ($Context.ActivationInfo.HasBroadActivation) { Get-HitLabels -Hits $Context.ActivationInfo.Hits } else { '' } },
        @{ Prefix = 'API'; Value = (Get-HitLabels -Hits $apiHits) },
        @{ Prefix = 'Outbound'; Value = (Get-HitLabels -Hits $networkHits) },
        @{ Prefix = 'Secrets'; Value = (Get-HitLabels -Hits @($secretPathHits + $secretEnvHits)) },
        @{ Prefix = 'Persistence'; Value = (Get-HitLabels -Hits $persistenceHits) },
        @{ Prefix = 'Obfuscation'; Value = (Get-HitLabels -Hits $obfuscationHits) },
        @{ Prefix = 'Packaging'; Value = (Get-HitLabels -Hits $packagingHits) },
        @{ Prefix = 'Keywords'; Value = (Get-HitLabels -Hits $keywordHits) }
    )

    [pscustomobject]@{
        Severity       = $severity
        Type           = $type
        Path           = $File.FullName
        PackageName    = $Identity.Name
        Version        = $Identity.Version
        Indicator      = "VS Code extension heuristic score $score — $((($indicatorParts | Select-Object -Unique) -join ', '))"
        Evidence       = $evidence
        Recommendation = Get-Recommendation -Severity $severity
    }
}

function Add-Finding {
    param(
        [System.Collections.Generic.List[object]]$List,
        $Finding
    )

    if ($null -ne $Finding) {
        $List.Add([pscustomobject]@{
            Severity       = $Finding.Severity
            Type           = $Finding.Type
            Path           = $Finding.Path
            PackageName    = $Finding.PackageName
            Version        = $Finding.Version
            Indicator      = $Finding.Indicator
            Evidence       = $Finding.Evidence
            Recommendation = $Finding.Recommendation
        })
    }
}

$results = New-Object 'System.Collections.Generic.List[object]'
$identity = Get-ProjectIdentity -FolderPath $ScanPath
$context = Get-ExtensionManifestContext -FolderPath $ScanPath

if (-not $context.IsExtension) {
    Write-DebugLog -Message "Folder does not look like a VS Code/Open VSX extension: $ScanPath"
}

try {
    $files = Get-ChildItem -LiteralPath $ScanPath -File -Force -ErrorAction Stop | Where-Object { Test-IsTargetFile -File $_ }
}
catch {
    $files = @()
}

foreach ($file in $files) {
    if ($file.Name -eq 'package.json') {
        Add-Finding -List $results -Finding (Analyze-PackageManifest -File $file -Context $context -Identity $identity)
        continue
    }

    Add-Finding -List $results -Finding (Analyze-TextFile -File $file -Context $context -Identity $identity)
}

$results