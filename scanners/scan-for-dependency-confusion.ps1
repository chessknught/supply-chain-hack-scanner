# © 2026 Sooke Software — Ted Neustaedter.
# Licensed under the GNU General Public License, version 3 or later.
#
# scan-for-dependency-confusion.ps1 — scans a single folder (non-recursive) for
# local indicators of dependency confusion risk: internal-looking unscoped package
# names, missing or misconfigured private registry pinning, Python public-fallback
# index configuration, and cross-manifest/lockfile evidence that suspicious names
# are actually resolved.
#
# This is a local offline heuristic scanner. No network calls are made.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScanPath,

    [int]$VerbosityLevel = 0
)

$ErrorActionPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# Internal / private naming cue words.
# A dependency name that contains one or more of these tokens as word-level
# components is considered internal-looking.
# Extend freely — each entry drives the scoring heuristic.
# ---------------------------------------------------------------------------
$InternalCueWords = @(
    'internal', 'private', 'corp', 'corporate', 'company',
    'shared', 'common', 'platform', 'sdk', 'core', 'base',
    'infra', 'infrastructure', 'auth', 'tenant', 'enterprise',
    'plugin', 'plugins', 'extension', 'extensions',
    'service', 'services', 'client', 'server', 'api',
    'lib', 'library', 'util', 'utils', 'helper', 'helpers', 'toolkit',
    'framework', 'engine', 'runtime', 'daemon', 'agent'
)

# ---------------------------------------------------------------------------
# Private / internal registry host patterns (lower-case substrings).
# Any config or CI file whose text contains one of these substrings is treated
# as evidence that a private feed is configured for this project.
# Extend to cover your own intranet hostnames.
# ---------------------------------------------------------------------------
$PrivateRegistryPatterns = @(
    'artifactory', 'jfrog',
    'nexus', 'sonatype',
    'pkgs.dev.azure.com', 'pkgs.visualstudio.com',
    'npm.pkg.github.com',
    'verdaccio',
    'proget', 'inedo',
    'registry.corp', 'registry.internal', 'registry.local',
    'npm.internal', 'pypi.internal', 'nuget.internal',
    '.intranet.', '.internal.', '.corp.'
)

# ---------------------------------------------------------------------------
# Environment variable names that indicate private package feed usage.
# Matched in CI files (Dockerfile, docker-compose, .env).
# ---------------------------------------------------------------------------
$FeedEnvVarPatterns = @(
    'NPM_CONFIG_REGISTRY', 'NPM_TOKEN', 'NPM_AUTH_TOKEN',
    'PIP_INDEX_URL', 'PIP_EXTRA_INDEX_URL', 'PIP_TRUSTED_HOST',
    'POETRY_HTTP_BASIC_', 'POETRY_PYPI_TOKEN_',
    'NUGET_ENDPOINT', 'VSS_NUGET_EXTERNAL_FEED_ENDPOINTS', 'NUGET_TOKEN',
    'CODEARTIFACT_AUTH_TOKEN', 'AWS_CODEARTIFACT_',
    'ARTIFACTORY_API_KEY', 'ARTIFACTORY_TOKEN', 'JFROG_TOKEN',
    'NEXUS_TOKEN', 'NEXUS_PASSWORD',
    'CARGO_REGISTRIES_', 'CARGO_REGISTRY_TOKEN',
    'GEMFURY_TOKEN', 'GEM_HOST_TOKEN'
)

# ---------------------------------------------------------------------------
# Python public-fallback config patterns.
# extra-index-url causes pip to resolve dependencies from a secondary
# (potentially public) index if the primary index does not have the package.
# ---------------------------------------------------------------------------
$PythonFallbackPatterns = @(
    'extra-index-url',
    'extra_index_url',
    '--extra-index-url'
)

# ---------------------------------------------------------------------------
# Manifest and lockfiles whose dependency declarations should be inspected.
# ---------------------------------------------------------------------------
$ManifestFiles = @(
    'package.json',
    'package-lock.json',
    'npm-shrinkwrap.json',
    'yarn.lock',
    'pnpm-lock.yaml',
    'requirements.txt',
    'pyproject.toml',
    'Pipfile',
    'setup.py',
    'setup.cfg',
    'poetry.lock',
    'go.mod',
    'Cargo.toml',
    'Gemfile',
    'packages.config',
    'Directory.Packages.props',
    'paket.dependencies',
    'pom.xml',
    'build.gradle',
    'settings.gradle'
)

# Subset of ManifestFiles that are lock / resolved-dependency files.
# A suspicious name appearing in both a primary manifest AND a lockfile
# provides higher confidence and receives an escalated severity.
$LockfileNames = @(
    'package-lock.json',
    'npm-shrinkwrap.json',
    'yarn.lock',
    'pnpm-lock.yaml',
    'poetry.lock'
)

# ---------------------------------------------------------------------------
# Config files to inspect for private feed / registry configuration.
# ---------------------------------------------------------------------------
$RegistryConfigFiles = @(
    '.npmrc',
    '.yarnrc',
    '.yarnrc.yml',
    '.pypirc',
    'pip.conf',
    'gradle.properties',
    'nuget.config'
)

# ---------------------------------------------------------------------------
# CI / deployment files to inspect for private-feed environment variables.
# ---------------------------------------------------------------------------
$CIFiles = @(
    'Dockerfile',
    'docker-compose.yml',
    'docker-compose.yaml',
    '.env',
    '.env.local',
    '.env.production'
)

# ── Generic helpers ──────────────────────────────────────────────────────────

function Get-FileText {
    param([string]$Path)
    try { Get-Content -LiteralPath $Path -Raw -ErrorAction Stop }
    catch { $null }
}

function Get-JsonFile {
    param([string]$Path)
    try { Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 20 }
    catch { $null }
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
        -Severity       $Severity `
        -Type           $Type `
        -Path           $Path `
        -PackageName    $PackageName `
        -Version        $Version `
        -Indicator      $Indicator `
        -Evidence       $Evidence `
        -Recommendation $Recommendation))
}

# ── Domain helpers ───────────────────────────────────────────────────────────

# Read the project name and version from package.json if present in the folder.
function Get-ProjectIdentity {
    param([string]$FolderPath)
    $pkgPath = Join-Path $FolderPath 'package.json'
    if (Test-Path -LiteralPath $pkgPath) {
        $json = Get-JsonFile $pkgPath
        if ($json) {
            return @{
                Name    = [string]($json.name    ?? '')
                Version = [string]($json.version ?? '')
            }
        }
    }
    @{ Name = ''; Version = '' }
}

# Count how many $InternalCueWords appear as word-boundary tokens in $DepName.
function Get-InternalCueScore {
    param([string]$DepName)
    $lower = $DepName.ToLower()
    $count = 0
    foreach ($cue in $InternalCueWords) {
        if ([regex]::IsMatch($lower,
            "(^|[-_./])$([regex]::Escape($cue))([-_./]|$)",
            [Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
            $count++
        }
    }
    $count
}

# Extract the leading org/company-like prefix token of a dependency name.
# "contoso-auth-sdk" → "contoso".  Returns '' if no clear prefix exists.
function Get-PackagePrefix {
    param([string]$DepName)
    $stripped = $DepName -replace '^@[^/]+/', ''       # strip npm @scope/
    $parts    = $stripped -split '[-_.]'
    if ($parts.Count -ge 2 -and $parts[0].Length -ge 3) {
        return $parts[0].ToLower()
    }
    ''
}

# Scan config and CI files in the folder for any evidence of private feed config.
# Returns a short summary string if found, '' if nothing detected.
function Get-RegistryConfigSummary {
    param([string]$FolderPath)
    $found = [System.Collections.Generic.List[string]]::new()

    foreach ($cf in $RegistryConfigFiles) {
        $cfPath = Join-Path $FolderPath $cf
        if (-not (Test-Path -LiteralPath $cfPath)) { continue }
        $text = Get-FileText $cfPath
        if ([string]::IsNullOrWhiteSpace($text)) { continue }

        foreach ($pat in $PrivateRegistryPatterns) {
            if ([regex]::IsMatch($text, [regex]::Escape($pat),
                    [Text.RegularExpressions.RegexOptions]::IgnoreCase)) {
                $found.Add("$cf → '$pat'")
                break
            }
        }

        # .npmrc: also look for scoped registry pins:  @scope:registry=https://...
        if ($cf -eq '.npmrc' -and
            [regex]::IsMatch($text, '(?m)^@[a-z0-9\-]+:registry\s*=')) {
            if (-not ($found | Where-Object { $_ -match [regex]::Escape($cf) + '.*scoped' })) {
                $found.Add('.npmrc → scoped registry mapping')
            }
        }
    }

    foreach ($cf in $CIFiles) {
        $cfPath = Join-Path $FolderPath $cf
        if (-not (Test-Path -LiteralPath $cfPath)) { continue }
        $text = Get-FileText $cfPath
        if ([string]::IsNullOrWhiteSpace($text)) { continue }

        foreach ($envVar in $FeedEnvVarPatterns) {
            if ($text.IndexOf($envVar, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
                $found.Add("$cf → env '$envVar'")
                break
            }
        }
    }

    if ($found.Count -eq 0) { return '' }
    $found -join '; '
}

# Return $true if .npmrc in the folder has a global 'registry=' line.
function Test-NpmrcGlobalRegistry {
    param([string]$FolderPath)
    $p = Join-Path $FolderPath '.npmrc'
    if (-not (Test-Path -LiteralPath $p)) { return $false }
    $text = Get-FileText $p
    if ([string]::IsNullOrWhiteSpace($text)) { return $false }
    [regex]::IsMatch($text, '(?m)^registry\s*=')
}

# Return $true if .npmrc in the folder has any per-scope registry pin.
function Test-NpmrcHasScopePin {
    param([string]$FolderPath)
    $p = Join-Path $FolderPath '.npmrc'
    if (-not (Test-Path -LiteralPath $p)) { return $false }
    $text = Get-FileText $p
    if ([string]::IsNullOrWhiteSpace($text)) { return $false }
    [regex]::IsMatch($text, '(?m)^@[a-z0-9\-]+:registry\s*=')
}

# ── Dependency extractors ────────────────────────────────────────────────────
# Each function accepts an absolute file path and emits package names to the
# pipeline. Returns nothing (silently) on any read or parse errors.

function Get-DepsFromPackageJson {
    param([string]$FilePath)
    $json = Get-JsonFile $FilePath
    if (-not $json) { return }
    foreach ($section in @('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies')) {
        $sec = $json.$section
        if ($sec) { $sec.PSObject.Properties.Name }
    }
}

function Get-DepsFromPackageLock {
    param([string]$FilePath)
    $json = Get-JsonFile $FilePath
    if (-not $json) { return }
    # v1: top-level "dependencies" keys
    if ($json.dependencies) { $json.dependencies.PSObject.Properties.Name }
    # v2/v3: "packages" keys like "node_modules/name"
    if ($json.packages) {
        $json.packages.PSObject.Properties.Name |
            Where-Object { $_ -like 'node_modules/*' } |
            ForEach-Object { $_ -replace '^node_modules/', '' }
    }
}

function Get-DepsFromYarnLock {
    param([string]$FilePath)
    $text = Get-FileText $FilePath
    if ($null -eq $text) { return }
    # Lines: "name@^x.y.z":  or  "@scope/name@^x.y.z":
    $re = [regex]::new('(?m)^"?(@?[A-Za-z0-9][A-Za-z0-9\-_\./@]*)@')
    foreach ($m in $re.Matches($text)) { $m.Groups[1].Value.TrimStart('"') }
}

function Get-DepsFromPnpmLock {
    param([string]$FilePath)
    $text = Get-FileText $FilePath
    if ($null -eq $text) { return }
    # Lines: "  /name@x.y.z:"  or  "  /@scope/name@x.y.z:"
    $re = [regex]::new('(?m)^\s+/(@?[A-Za-z0-9][A-Za-z0-9\-_\./@]*)@')
    foreach ($m in $re.Matches($text)) { $m.Groups[1].Value }
}

function Get-DepsFromRequirementsTxt {
    param([string]$FilePath)
    $text = Get-FileText $FilePath
    if ($null -eq $text) { return }
    foreach ($line in ($text -split "`n")) {
        $trimmed = $line.Trim()
        if ($trimmed -eq '' -or $trimmed -like '#*' -or $trimmed -like '-*') { continue }
        $m = [regex]::Match($trimmed, '^([A-Za-z0-9][A-Za-z0-9\-_\.]*)')
        if ($m.Success) { $m.Groups[1].Value }
    }
}

function Get-DepsFromPoetryLock {
    param([string]$FilePath)
    $text = Get-FileText $FilePath
    if ($null -eq $text) { return }
    $re = [regex]::new('(?m)^name\s*=\s*"([^"]+)"')
    foreach ($m in $re.Matches($text)) { $m.Groups[1].Value }
}

function Get-DepsFromGenericText {
    # Heuristic extractor for pyproject.toml, Pipfile, setup.cfg.
    # Extracts quoted names that look like package identifiers.
    param([string]$FilePath)
    $text = Get-FileText $FilePath
    if ($null -eq $text) { return }
    $re = [regex]::new('"([A-Za-z0-9][A-Za-z0-9\-_\.]+)[^"]*"')
    foreach ($m in $re.Matches($text)) { $m.Groups[1].Value }
}

function Get-DepsFromSetupPy {
    param([string]$FilePath)
    $text = Get-FileText $FilePath
    if ($null -eq $text) { return }
    # \x22 = double-quote hex escape; single-quote is literal in .NET regex char class.
    $re = [regex]::new("['\x22]([A-Za-z0-9][A-Za-z0-9\-_\.]+)['\x22]")
    foreach ($m in $re.Matches($text)) { $m.Groups[1].Value }
}

function Get-DepsFromGoMod {
    param([string]$FilePath)
    $text = Get-FileText $FilePath
    if ($null -eq $text) { return }
    foreach ($line in ($text -split "`n")) {
        $m = [regex]::Match($line.Trim(), '^([A-Za-z0-9][A-Za-z0-9.\-_/]+)\s+v[0-9]')
        if ($m.Success) {
            $parts = $m.Groups[1].Value -split '/'
            $parts[-1]   # emit the final path segment as the module short name
        }
    }
}

function Get-DepsFromCargoToml {
    param([string]$FilePath)
    $text = Get-FileText $FilePath
    if ($null -eq $text) { return }
    $inDeps = $false
    foreach ($line in ($text -split "`n")) {
        $trimmed = $line.Trim()
        if ($trimmed -match '^\[.*dependencies') { $inDeps = $true;  continue }
        if ($trimmed -match '^\[')               { $inDeps = $false; continue }
        if ($inDeps) {
            $m = [regex]::Match($trimmed, '^([A-Za-z0-9][A-Za-z0-9\-_]*)\s*=')
            if ($m.Success) { $m.Groups[1].Value }
        }
    }
}

function Get-DepsFromGemfile {
    param([string]$FilePath)
    $text = Get-FileText $FilePath
    if ($null -eq $text) { return }
    # Match: gem 'name' or gem "name"  (hex \x22 = double quote to avoid quoting issues)
    $re = [regex]::new("(?m)^\s*gem\s+['\x22]([A-Za-z0-9][A-Za-z0-9\-_\.]*)")
    foreach ($m in $re.Matches($text)) { $m.Groups[1].Value }
}

function Get-DepsFromPomXml {
    param([string]$FilePath)
    $text = Get-FileText $FilePath
    if ($null -eq $text) { return }
    $re = [regex]::new('<artifactId>([^<]+)</artifactId>')
    foreach ($m in $re.Matches($text)) { $m.Groups[1].Value }
}

function Get-DepsFromBuildGradle {
    param([string]$FilePath)
    $text = Get-FileText $FilePath
    if ($null -eq $text) { return }
    # Match  'group:artifact:version'  or  "group:artifact:version"
    # \x22 = double-quote hex escape so the PS string delimiter is not confused.
    $re = [regex]::new("['\x22]([A-Za-z0-9.\-_]+):([A-Za-z0-9.\-_]+):[^'\x22]*['\x22]")
    foreach ($m in $re.Matches($text)) { $m.Groups[2].Value }
}

function Get-DepsFromPackagesConfig {
    param([string]$FilePath)
    $text = Get-FileText $FilePath
    if ($null -eq $text) { return }
    $re = [regex]::new('<package[^>]+id="([^"]+)"', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($m in $re.Matches($text)) { $m.Groups[1].Value }
}

function Get-DepsFromPackageVersionProps {
    param([string]$FilePath)
    $text = Get-FileText $FilePath
    if ($null -eq $text) { return }
    $re = [regex]::new('<PackageVersion[^>]+Include="([^"]+)"', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($m in $re.Matches($text)) { $m.Groups[1].Value }
}

function Get-DepsFromCsproj {
    param([string]$FilePath)
    $text = Get-FileText $FilePath
    if ($null -eq $text) { return }
    $re = [regex]::new('<PackageReference[^>]+Include="([^"]+)"', [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    foreach ($m in $re.Matches($text)) { $m.Groups[1].Value }
}

function Get-DepsFromPaket {
    param([string]$FilePath)
    $text = Get-FileText $FilePath
    if ($null -eq $text) { return }
    foreach ($line in ($text -split "`n")) {
        $m = [regex]::Match($line.Trim(), '^(?:nuget|github|http)\s+([A-Za-z0-9][A-Za-z0-9.\-_]+)')
        if ($m.Success) { $m.Groups[1].Value }
    }
}

# ── Helper: route a file to its extractor and store results ──────────────────
# Populates $primaryManifestDeps and $lockfileDeps (script-level hashtables).
function Add-FileDeps {
    param([string]$FileName, [string]$FilePath, [bool]$IsLockfile)

    $deps = switch ($FileName) {
        'package.json'                                              { @(Get-DepsFromPackageJson      $FilePath) }
        { $_ -in @('package-lock.json', 'npm-shrinkwrap.json') }   { @(Get-DepsFromPackageLock      $FilePath) }
        'yarn.lock'                                                 { @(Get-DepsFromYarnLock         $FilePath) }
        'pnpm-lock.yaml'                                           { @(Get-DepsFromPnpmLock         $FilePath) }
        'requirements.txt'                                         { @(Get-DepsFromRequirementsTxt  $FilePath) }
        { $_ -in @('pyproject.toml', 'Pipfile') }                  { @(Get-DepsFromGenericText      $FilePath) }
        { $_ -in @('setup.py', 'setup.cfg') }                      { @(Get-DepsFromSetupPy          $FilePath) }
        'poetry.lock'                                              { @(Get-DepsFromPoetryLock       $FilePath) }
        'go.mod'                                                    { @(Get-DepsFromGoMod            $FilePath) }
        'Cargo.toml'                                               { @(Get-DepsFromCargoToml        $FilePath) }
        'Gemfile'                                                   { @(Get-DepsFromGemfile         $FilePath) }
        'packages.config'                                           { @(Get-DepsFromPackagesConfig   $FilePath) }
        'Directory.Packages.props'                                  { @(Get-DepsFromPackageVersionProps $FilePath) }
        'paket.dependencies'                                        { @(Get-DepsFromPaket            $FilePath) }
        'pom.xml'                                                   { @(Get-DepsFromPomXml           $FilePath) }
        { $_ -in @('build.gradle', 'settings.gradle') }            { @(Get-DepsFromBuildGradle      $FilePath) }
        default                                                     { @() }
    }

    foreach ($dep in ($deps | Where-Object { $_ -and $_.Trim() } | Select-Object -Unique)) {
        if ($IsLockfile) {
            if (-not $script:lockfileDeps.Contains($dep)) { $script:lockfileDeps[$dep] = $FilePath }
        } else {
            if (-not $script:primaryManifestDeps.Contains($dep)) { $script:primaryManifestDeps[$dep] = $FilePath }
        }
    }
}

# ── Main scan body ────────────────────────────────────────────────────────────

$results = New-Object 'System.Collections.Generic.List[object]'

# ── 1. Project identity ───────────────────────────────────────────────────────
$identity         = Get-ProjectIdentity $ScanPath
$folderPkgName    = $identity.Name
$folderPkgVersion = $identity.Version

# ── 2. Registry / feed configuration present in this folder? ─────────────────
$registryConfigSummary  = Get-RegistryConfigSummary $ScanPath
$hasRegistryConfig      = $registryConfigSummary -ne ''
$hasNpmrcScopePin       = Test-NpmrcHasScopePin    $ScanPath
$hasNpmrcGlobalOverride = Test-NpmrcGlobalRegistry  $ScanPath

# ── 3. Collect dependency names, keyed by source file path ───────────────────
$script:primaryManifestDeps = [ordered]@{}   # dep name → absolute manifest path
$script:lockfileDeps        = [ordered]@{}   # dep name → absolute lockfile path

foreach ($mf in $ManifestFiles) {
    $mfPath = Join-Path $ScanPath $mf
    if (-not (Test-Path -LiteralPath $mfPath)) { continue }
    Add-FileDeps -FileName $mf -FilePath $mfPath -IsLockfile ($LockfileNames -contains $mf)
}

# Glob *.csproj (may have any base name)
try {
    Get-ChildItem -LiteralPath $ScanPath -File -Filter '*.csproj' -ErrorAction Stop |
        ForEach-Object {
            $csprojDeps = @(Get-DepsFromCsproj $_.FullName | Where-Object { $_ } | Select-Object -Unique)
            foreach ($dep in $csprojDeps) {
                if (-not $script:primaryManifestDeps.Contains($dep)) {
                    $script:primaryManifestDeps[$dep] = $_.FullName
                }
            }
        }
} catch { }

# ── 4. Build org-prefix cluster map ──────────────────────────────────────────
# prefixGroups: prefix token → list of dep names sharing that leading token.
$prefixGroups = @{}
foreach ($dep in $script:primaryManifestDeps.Keys) {
    $prefix = Get-PackagePrefix $dep
    if ($prefix -eq '') { continue }
    if (-not $prefixGroups.ContainsKey($prefix)) {
        $prefixGroups[$prefix] = [System.Collections.Generic.List[string]]::new()
    }
    $prefixGroups[$prefix].Add($dep)
}
# Only prefixes shared by 2 or more dependencies are considered clusters.
$clusterPrefixes = @($prefixGroups.Keys | Where-Object { $prefixGroups[$_].Count -ge 2 })

# ── 5. Score each primary dep and emit findings ───────────────────────────────
foreach ($dep in $script:primaryManifestDeps.Keys) {
    $cueScore = Get-InternalCueScore $dep
    if ($cueScore -eq 0) { continue }

    $sourcePath = $script:primaryManifestDeps[$dep]
    $sourceFile = Split-Path $sourcePath -Leaf
    $isNpmFile  = $sourceFile -in @('package.json', 'package-lock.json',
                                     'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml')
    $isUnscoped = -not $dep.StartsWith('@')

    # Base severity
    $severity = if ($cueScore -ge 2) { 'Medium' } else { 'Info' }

    # Escalation A: no registry config in this folder at all
    if (-not $hasRegistryConfig) {
        $severity = if ($cueScore -ge 2) { 'HIGH' } else { 'Medium' }
    }

    # Escalation B: npm ecosystem, unscoped name, no @scope:registry= pinning in .npmrc
    if ($isNpmFile -and $isUnscoped -and -not $hasNpmrcScopePin) {
        if ($severity -ne 'HIGH') {
            $severity = if ($cueScore -ge 2) { 'HIGH' } else { 'Medium' }
        }
    }

    # Escalation C: shares an org prefix with 2+ other deps (higher naming confidence)
    $prefix      = Get-PackagePrefix $dep
    $sharedPeers = @()
    if ($prefix -ne '' -and $clusterPrefixes -contains $prefix) {
        $sharedPeers = @($prefixGroups[$prefix] | Where-Object { $_ -ne $dep })
        if ($sharedPeers.Count -ge 1 -and $severity -ne 'HIGH') {
            $severity = if ($hasRegistryConfig) { 'Medium' } else { 'HIGH' }
        }
    }

    # Escalation D: dep is also present in a lockfile (confirmed resolved)
    $inLockfile     = $script:lockfileDeps.Contains($dep)
    $lockfileSource = if ($inLockfile) { Split-Path $script:lockfileDeps[$dep] -Leaf } else { '' }
    if ($inLockfile -and $severity -ne 'HIGH') { $severity = 'HIGH' }

    # Build evidence
    $evidenceParts = [System.Collections.Generic.List[string]]::new()
    $evidenceParts.Add("$cueScore internal cue word(s) matched")
    $evidenceParts.Add("found in: $sourceFile")
    if ($inLockfile)              { $evidenceParts.Add("also resolved in lockfile: $lockfileSource") }
    if ($sharedPeers.Count -ge 1) { $evidenceParts.Add("shares prefix '$prefix' with: $($sharedPeers -join ', ')") }
    if ($hasRegistryConfig)       { $evidenceParts.Add("registry cfg present: $registryConfigSummary") }
    else                          { $evidenceParts.Add('no private registry config detected in this folder') }

    $indicator = "Internal-looking unscoped dependency '$dep'"
    $rec = switch ($severity) {
        'HIGH'   { "Investigate '$dep': strong internal-naming signal with insufficient feed-pinning. Confirm it cannot be resolved from a public registry. Consider scoping as @org/$dep or adding a private-registry pin." }
        'Medium' { "Review '$dep': name contains internal-style tokens that may resolve from a public registry. Verify your package manager config explicitly pins this name to a private feed." }
        default  { "Low-confidence signal on '$dep': contains internal naming cues. Confirm this is intentional and that the package is publicly available." }
    }

    Add-Finding -List $results `
        -Severity       $severity `
        -Type           'DependencyConfusion' `
        -Path           $sourcePath `
        -PackageName    $folderPkgName `
        -Version        $folderPkgVersion `
        -Indicator      $indicator `
        -Evidence       ($evidenceParts -join ' | ') `
        -Recommendation $rec
}

# ── 6. Python extra-index-url / public fallback risk ─────────────────────────
foreach ($pf in @('requirements.txt', 'pyproject.toml', 'Pipfile', 'setup.cfg', '.pypirc', 'pip.conf')) {
    $pfPath = Join-Path $ScanPath $pf
    if (-not (Test-Path -LiteralPath $pfPath)) { continue }
    $text = Get-FileText $pfPath
    if ([string]::IsNullOrWhiteSpace($text)) { continue }
    foreach ($pat in $PythonFallbackPatterns) {
        if ($text.IndexOf($pat, [StringComparison]::OrdinalIgnoreCase) -ge 0) {
            Add-Finding -List $results `
                -Severity       'Medium' `
                -Type           'DependencyConfusion' `
                -Path           $pfPath `
                -PackageName    $folderPkgName `
                -Version        $folderPkgVersion `
                -Indicator      "Python extra-index-url in $pf allows public PyPI fallback" `
                -Evidence       "Pattern '$pat' found — packages absent from the primary index may fall through to public PyPI" `
                -Recommendation 'Use only index-url (not extra-index-url) to block public fallback, or confirm that no internal package names are claimable on public PyPI.'
            break   # one finding per file is sufficient
        }
    }
}

# ── 7. .npmrc global registry override without per-scope pinning ──────────────
if ($hasNpmrcGlobalOverride -and -not $hasNpmrcScopePin) {
    $npmrcPath = Join-Path $ScanPath '.npmrc'
    Add-Finding -List $results `
        -Severity       'Medium' `
        -Type           'DependencyConfusion' `
        -Path           $npmrcPath `
        -PackageName    $folderPkgName `
        -Version        $folderPkgVersion `
        -Indicator      '.npmrc overrides global registry but has no per-scope pinning' `
        -Evidence       'registry= line is present but no @scope:registry= mapping — unscoped internal-looking package names may still resolve from public npm' `
        -Recommendation 'Add per-scope registry mappings (e.g. @myorg:registry=https://your-feed) to .npmrc so internal package names are pinned to your private registry.'
}

# ── 8. Cargo.toml: alternate registry defined but no dep pinned to it ─────────
$cargoPath = Join-Path $ScanPath 'Cargo.toml'
if (Test-Path -LiteralPath $cargoPath) {
    $cargoText = Get-FileText $cargoPath
    if (-not [string]::IsNullOrWhiteSpace($cargoText)) {
        $hasAltReg  = [regex]::IsMatch($cargoText, '\[registries\.')
        $hasPinned  = [regex]::IsMatch($cargoText, 'registry\s*=\s*"')
        if ($hasAltReg -and -not $hasPinned) {
            Add-Finding -List $results `
                -Severity       'Medium' `
                -Type           'DependencyConfusion' `
                -Path           $cargoPath `
                -PackageName    $folderPkgName `
                -Version        $folderPkgVersion `
                -Indicator      'Cargo.toml defines alternate registries but no crate is pinned to one' `
                -Evidence       '[registries.*] section found but no registry = "..." assignment in [dependencies]' `
                -Recommendation 'Pin crates to their intended private registry using registry = "your-registry-name" in Cargo.toml.'
        }
    }
}

# ── 9. Info: registry config present but no suspicious dep names found ─────────
if ($hasRegistryConfig -and $results.Count -eq 0) {
    $firstCfPath = ''
    foreach ($cf in ($RegistryConfigFiles + $CIFiles)) {
        $cfp = Join-Path $ScanPath $cf
        if (Test-Path -LiteralPath $cfp) { $firstCfPath = $cfp; break }
    }
    if ($firstCfPath) {
        Add-Finding -List $results `
            -Severity       'Info' `
            -Type           'DependencyConfusion' `
            -Path           $firstCfPath `
            -PackageName    $folderPkgName `
            -Version        $folderPkgVersion `
            -Indicator      'Private registry/feed configuration detected' `
            -Evidence       "Config: $registryConfigSummary" `
            -Recommendation 'Confirm all dependencies are correctly scoped or pinned to the private registry to prevent public-registry fallback.'
    }
}

$results
