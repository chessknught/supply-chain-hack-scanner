# © 2026 Sooke Software — Ted Neustaedter. All rights reserved.

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScanPath,

    [int]$VerbosityLevel = 0
)

$ErrorActionPreference = 'SilentlyContinue'

# ---------------------------------------------------------------------------
# Well-known popular package names across ecosystems.
# Extend this list freely — it drives all similarity checks.
# ---------------------------------------------------------------------------
$KnownPackages = @(
    # npm — UI frameworks and core libraries
    'react', 'react-dom', 'react-router', 'react-router-dom', 'react-redux',
    'vue', 'vue-router', 'nuxt', 'angular', 'next',
    'svelte', 'solid-js', 'preact', 'lit', 'ember',

    # npm — build / tooling
    'webpack', 'vite', 'rollup', 'parcel', 'esbuild', 'turbo',
    'typescript', 'ts-node', 'babel', 'eslint', 'prettier', 'jest',
    'mocha', 'chai', 'vitest', 'swc',

    # npm — runtime utilities
    'axios', 'express', 'fastify', 'koa', 'hapi',
    'lodash', 'underscore', 'ramda', 'moment', 'dayjs', 'date-fns',
    'chalk', 'colors', 'debug', 'dotenv', 'commander', 'yargs',
    'uuid', 'nanoid', 'zod', 'joi', 'ajv',
    'socket.io', 'ws', 'got', 'node-fetch', 'superagent', 'request',
    'multer', 'formidable', 'busboy',
    'jsonwebtoken', 'bcrypt', 'bcryptjs', 'passport',
    'sequelize', 'mongoose', 'prisma', 'typeorm', 'knex',
    'redis', 'ioredis', 'mysql2', 'pg', 'sqlite3',
    'nodemailer', 'winston', 'pino', 'morgan',
    'body-parser', 'cors', 'helmet', 'compression',
    'cross-env', 'rimraf', 'glob', 'chokidar', 'fs-extra',
    'semver', 'minimatch', 'micromatch',
    'classnames', 'tailwindcss', 'styled-components', 'emotion',
    'redux', 'mobx', 'zustand', 'recoil', 'jotai',
    'graphql', 'apollo-client', 'apollo-server',

    # Python
    'requests', 'flask', 'django', 'fastapi', 'uvicorn', 'gunicorn',
    'numpy', 'pandas', 'scipy', 'matplotlib', 'seaborn', 'pillow',
    'torch', 'tensorflow', 'keras', 'scikit-learn', 'xgboost', 'lightgbm',
    'boto3', 'botocore', 'pydantic', 'sqlalchemy', 'alembic',
    'celery', 'redis', 'pymongo', 'psycopg2', 'httpx', 'aiohttp',
    'beautifulsoup4', 'selenium', 'playwright', 'scrapy',
    'pytest', 'mypy', 'black', 'ruff', 'isort', 'flake8',
    'cryptography', 'paramiko', 'fabric', 'click', 'rich', 'typer',
    'pyjwt', 'passlib', 'urllib3', 'certifi', 'charset-normalizer', 'idna',
    'jinja2', 'mako', 'marshmallow', 'attrs', 'pydantic-settings',

    # Go (module short names)
    'gin', 'echo', 'fiber', 'chi', 'gorilla',

    # Rust
    'serde', 'tokio', 'actix-web', 'reqwest', 'anyhow', 'thiserror',
    'clap', 'log', 'tracing', 'rayon', 'chrono',

    # Ruby
    'rails', 'sinatra', 'devise', 'rspec', 'bundler', 'rake', 'capistrano'
)

# ---------------------------------------------------------------------------
# Words that imply legitimacy but are used as bait in typosquat names.
# ---------------------------------------------------------------------------
$BaitWords = @(
    'official', 'secure', 'secured', 'security',
    'trusted', 'verified', 'verified-',
    'enterprise', 'internal', 'private',
    'core', 'pro', 'plus', 'premium',
    'team', 'tools', 'util', 'utils', 'helper', 'helpers',
    'fork', 'fixed', 'patched', 'stable', 'lts',
    'real', 'true', 'genuine', 'legit', 'safe'
)

# ---------------------------------------------------------------------------
# Suspicious scope/namespace patterns — publishers that look like
# well-known organizations but are slightly off.
# ---------------------------------------------------------------------------
$SuspiciousScopes = @(
    # Microsoft lookalikes
    '@microsoftt', '@micros0ft', '@micro-soft', '@microsoft-',
    # npm / Node lookalikes
    '@npmjs', '@npm-official', '@node-', '@nodejs-',
    # React / Meta lookalikes
    '@reactjs', '@reactjs-', '@react-official', '@facebookreact',
    # Angular / Google lookalikes
    '@angulars', '@angular-official', '@googler',
    # AWS lookalikes
    '@amazons', '@awss', '@aws-official',
    # known scoped packages someone might impersonate
    '@expressjs', '@vuejs-', '@nuxtjs-',
    '@babel-official', '@eslint-', '@typescript-official'
)

# ---------------------------------------------------------------------------
# Manifest files whose dependency sections will be inspected.
# ---------------------------------------------------------------------------
$TargetFiles = @(
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
    'go.mod',
    'Cargo.toml',
    'Gemfile'
)

# ---------------------------------------------------------------------------
# Helper: safely read a file as a raw string. Returns $null on any error.
# ---------------------------------------------------------------------------
function Get-FileText {
    param([string]$Path)
    try {
        Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    }
    catch { $null }
}

# ---------------------------------------------------------------------------
# Helper: safely parse JSON. Returns $null on any error.
# ---------------------------------------------------------------------------
function Get-JsonFile {
    param([string]$Path)
    try {
        Get-Content -LiteralPath $Path -Raw -ErrorAction Stop | ConvertFrom-Json -Depth 20
    }
    catch { $null }
}

# ---------------------------------------------------------------------------
# Helper: normalize a package name for comparison.
# Strips scope (@foo/), lowercases, removes separators (- _ .).
# ---------------------------------------------------------------------------
function Get-NormalizedName {
    param([string]$Name)
    $n = $Name.ToLower()
    $n = [regex]::Replace($n, '^@[^/]+/', '')   # strip scope
    $n = $n -replace '[-_\.]', ''                # strip separators
    $n
}

# ---------------------------------------------------------------------------
# Helper: compute Levenshtein distance between two strings.
# Returns an integer edit distance.
# ---------------------------------------------------------------------------
function Get-EditDistance {
    param([string]$A, [string]$B)
    $la = $A.Length; $lb = $B.Length
    if ($la -eq 0) { return $lb }
    if ($lb -eq 0) { return $la }
    $prev = 0..$lb
    for ($i = 1; $i -le $la; $i++) {
        $curr = New-Object int[] ($lb + 1)
        $curr[0] = $i
        for ($j = 1; $j -le $lb; $j++) {
            $cost = if ($A[$i-1] -eq $B[$j-1]) { 0 } else { 1 }
            $curr[$j] = [Math]::Min(
                [Math]::Min($curr[$j-1] + 1, $prev[$j] + 1),
                $prev[$j-1] + $cost
            )
        }
        $prev = $curr
    }
    $prev[$lb]
}

# ---------------------------------------------------------------------------
# Helper: detect transposition (two adjacent characters swapped).
# Returns $true if $Candidate is a single transposition of $Known.
# ---------------------------------------------------------------------------
function Test-IsTransposition {
    param([string]$Known, [string]$Candidate)
    if ($Known.Length -ne $Candidate.Length) { return $false }
    $diffs = @()
    for ($i = 0; $i -lt $Known.Length; $i++) {
        if ($Known[$i] -ne $Candidate[$i]) { $diffs += $i }
        if ($diffs.Count -gt 2) { return $false }
    }
    if ($diffs.Count -eq 2) {
        return ($Known[$diffs[0]] -eq $Candidate[$diffs[1]] -and
                $Known[$diffs[1]] -eq $Candidate[$diffs[0]])
    }
    return $false
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
# Core: analyze a single dependency name and return a finding hashtable
# (Severity/Reason/MatchedKnown) or $null if nothing suspicious.
# ---------------------------------------------------------------------------
function Get-TyposquatAssessment {
    param([string]$DepName)

    $signals   = [System.Collections.Generic.List[string]]::new()
    $matchedKnown = ''
    $severity  = $null

    $rawLower  = $DepName.ToLower()
    $norm      = Get-NormalizedName $DepName
    $hasScope  = $DepName.StartsWith('@')

    # ── 1. Suspicious scope lookalike ──────────────────────────────────────
    if ($hasScope) {
        $scope = '@' + ($DepName -replace '^@([^/]+)/.*', '$1').ToLower()
        foreach ($s in $SuspiciousScopes) {
            if ($scope -eq $s -or $scope.StartsWith($s)) {
                $signals.Add("Suspicious publisher scope: $scope")
                $severity = 'HIGH'
            }
        }
    }

    # ── 2. Bait-word in unscoped or scoped package name ───────────────────
    foreach ($bait in $BaitWords) {
        if ($rawLower -match "\b$([regex]::Escape($bait))\b") {
            # Only flag if a known package name also appears in the candidate
            foreach ($known in $KnownPackages) {
                $knownNorm = Get-NormalizedName $known
                if ($norm -match [regex]::Escape($knownNorm) -or
                    $rawLower -match [regex]::Escape($known)) {
                    $signals.Add("Bait word '$bait' combined with known package '$known'")
                    $matchedKnown = $known
                    if (-not $severity) { $severity = 'Medium' }
                }
            }
        }
    }

    # ── 3. Separator / normalization collision ────────────────────────────
    # e.g. react_dom vs react-dom, dot-env vs dotenv
    foreach ($known in $KnownPackages) {
        $knownNorm = Get-NormalizedName $known
        if ($knownNorm.Length -lt 4) { continue }   # too short to be reliable
        if ($norm -eq $knownNorm -and $rawLower -ne $known.ToLower()) {
            $signals.Add("Separator collision with '$known' (normalized both → '$knownNorm')")
            $matchedKnown = $known
            if (-not $severity) { $severity = 'Medium' }
        }
    }

    # ── 4. Edit-distance / transposition similarity ───────────────────────
    foreach ($known in $KnownPackages) {
        $knownNorm = Get-NormalizedName $known
        if ($knownNorm.Length -lt 4) { continue }

        # Skip if already exact same (covered above) or name contains the known
        # as a legitimate sub-word (e.g. 'react-hot-toast' contains 'react')
        if ($norm -eq $knownNorm) { continue }

        $dist = Get-EditDistance $norm $knownNorm

        # Thresholds: 1 edit for short names (≤8 chars), up to 2 for longer
        $maxDist = if ($knownNorm.Length -le 8) { 1 } else { 2 }
        if ($dist -le $maxDist -and $dist -gt 0) {
            $isTranspose = Test-IsTransposition $knownNorm $norm
            $desc = if ($isTranspose) { "transposition" } else { "$dist-char edit" }
            $signals.Add("$desc of '$known' (edit distance $dist)")
            $matchedKnown = $known

            # Promote severity: 1 edit is HIGH, 2 edits is Medium
            if ($dist -eq 1) {
                $severity = 'HIGH'
            } elseif (-not $severity) {
                $severity = 'Medium'
            }
        }
    }

    # ── 5. Prefix/suffix impersonation of known package ──────────────────
    # e.g. axios-js, secure-axios, node-react-core
    foreach ($known in $KnownPackages) {
        if ($known.Length -lt 4)       { continue }
        if ($rawLower -eq $known.ToLower()) { continue }  # exact match is fine

        $knownLower = $known.ToLower()
        $isDangerous = (
            $rawLower -match "^${knownLower}-" -or   # axios-xyz
            $rawLower -match "-${knownLower}$" -or   # xyz-axios
            $rawLower -match "^${knownLower}_" -or
            $rawLower -match "_${knownLower}$" -or
            $rawLower -match "^node-${knownLower}" -or
            $rawLower -match "^${knownLower}js$" -or  # axiosjs
            $rawLower -match "^${knownLower}\.js$"
        )
        if ($isDangerous) {
            # Suppress false positives: scoped ecosystem packages like
            # react-dom, react-router, redux-thunk are legitimate children.
            # Only flag when there is a bait word present OR the package
            # is completely unknown-looking (single word suffix).
            $hasBait = $false
            foreach ($bait in $BaitWords) {
                if ($rawLower -match "\b$([regex]::Escape($bait))\b") { $hasBait = $true; break }
            }
            if ($hasBait) {
                if (-not ($signals | Where-Object { $_ -match [regex]::Escape($known) })) {
                    $signals.Add("Prefix/suffix impersonation of '$known' with bait word")
                    $matchedKnown = $known
                    if (-not $severity) { $severity = 'Medium' }
                }
            }
        }
    }

    # ── 6. Repeated or doubled letters suggesting typo ────────────────────
    # e.g. axxios, reeact, loddash
    foreach ($known in $KnownPackages) {
        if ($known.Length -lt 4) { continue }
        $knownLower = $known.ToLower()
        if ($rawLower -eq $knownLower) { continue }
        # Build a pattern that allows any single character to be doubled
        $escapedKnown = [regex]::Escape($knownLower)
        $doubled = [regex]::new(
            ($knownLower.ToCharArray() | ForEach-Object {
                [regex]::Escape([string]$_) + '+'
            }) -join '',
            [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
        )
        if ($doubled.IsMatch($rawLower) -and $rawLower -ne $knownLower) {
            $normDist = Get-EditDistance $norm (Get-NormalizedName $known)
            if ($normDist -le 2) {
                if (-not ($signals | Where-Object { $_ -match [regex]::Escape($known) })) {
                    $signals.Add("Doubled/repeated character variant of '$known'")
                    $matchedKnown = $known
                    if ($normDist -eq 1 -and -not $severity) { $severity = 'HIGH' }
                    elseif (-not $severity) { $severity = 'Medium' }
                }
            }
        }
    }

    if ($signals.Count -eq 0) { return $null }

    # Multiple independent signals → escalate to HIGH
    if ($signals.Count -ge 2 -and $severity -ne 'HIGH') { $severity = 'HIGH' }

    return @{
        Severity     = $severity
        Signals      = $signals
        MatchedKnown = $matchedKnown
    }
}

# ---------------------------------------------------------------------------
# Helpers: extract dependency name lists from various manifest formats.
# All parsers are lenient — a parse failure returns an empty list.
# ---------------------------------------------------------------------------

function Get-NpmDepsFromJson {
    param($Obj)
    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($section in @('dependencies','devDependencies','optionalDependencies','peerDependencies')) {
        $block = $Obj.$section
        if ($block) {
            $block.PSObject.Properties | ForEach-Object { $names.Add($_.Name) }
        }
    }
    $names
}

function Get-NpmDepsFromLockJson {
    param($Obj)
    $names = [System.Collections.Generic.List[string]]::new()
    # v1 lock: dependencies object
    if ($Obj.dependencies) {
        $Obj.dependencies.PSObject.Properties | ForEach-Object { $names.Add($_.Name) }
    }
    # v2/v3 lock: packages object keys look like "node_modules/pkgname"
    if ($Obj.packages) {
        $Obj.packages.PSObject.Properties.Name | ForEach-Object {
            if ($_ -match '^node_modules/(.+)$') { $names.Add($Matches[1]) }
        }
    }
    $names
}

function Get-DepsFromYarnLock {
    param([string]$Text)
    # Yarn lock lines look like: "packagename@version:" or packagename@version:
    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($line in ($Text -split "`n")) {
        if ($line -match '^"?(@?[a-zA-Z0-9][a-zA-Z0-9\-_\.\/]*)@') {
            $names.Add($Matches[1])
        }
    }
    $names
}

function Get-DepsFromPnpmLock {
    param([string]$Text)
    # pnpm-lock.yaml dependency blocks: "  /packagename@version:"
    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($line in ($Text -split "`n")) {
        if ($line -match '^\s+/(@?[a-zA-Z0-9][a-zA-Z0-9\-_\.\/]*)@') {
            $names.Add($Matches[1])
        }
    }
    $names
}

function Get-DepsFromRequirementsTxt {
    param([string]$Text)
    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($line in ($Text -split "`n")) {
        $line = $line.Trim()
        if ($line -eq '' -or $line.StartsWith('#') -or $line.StartsWith('-')) { continue }
        if ($line -match '^([A-Za-z0-9][A-Za-z0-9\-_\.]*)\s*[>=<!;\[]') {
            $names.Add($Matches[1])
        } elseif ($line -match '^([A-Za-z0-9][A-Za-z0-9\-_\.]*)$') {
            $names.Add($Matches[1])
        }
    }
    $names
}

function Get-DepsFromPyprojectToml {
    param([string]$Text)
    $names = [System.Collections.Generic.List[string]]::new()
    $inDeps = $false
    foreach ($line in ($Text -split "`n")) {
        $trimmed = $line.Trim()
        if ($trimmed -match '^\[.*dependencies\]') { $inDeps = $true; continue }
        if ($trimmed.StartsWith('[') -and -not ($trimmed -match 'dependencies')) { $inDeps = $false }
        if ($inDeps -and $trimmed -match '^"?([A-Za-z0-9][A-Za-z0-9\-_\.]*)') {
            $names.Add($Matches[1])
        }
        # [project] dependencies = [ ... ] inline list
        if ($trimmed -match '"([A-Za-z0-9][A-Za-z0-9\-_\.]+)\s*[>=<!;\[]') {
            $names.Add($Matches[1])
        }
    }
    $names
}

function Get-DepsFromPipfile {
    param([string]$Text)
    $names = [System.Collections.Generic.List[string]]::new()
    $inDeps = $false
    foreach ($line in ($Text -split "`n")) {
        $trimmed = $line.Trim()
        if ($trimmed -match '^\[(packages|dev-packages)\]') { $inDeps = $true; continue }
        if ($trimmed.StartsWith('[')) { $inDeps = $false }
        if ($inDeps -and $trimmed -match '^([A-Za-z0-9][A-Za-z0-9\-_\.]*)\s*=') {
            $names.Add($Matches[1])
        }
    }
    $names
}

function Get-DepsFromSetupPy {
    param([string]$Text)
    $names = [System.Collections.Generic.List[string]]::new()
    $Text | Select-String -Pattern '"([A-Za-z0-9][A-Za-z0-9\-_\.]+)\s*[>=<!;\[]' -AllMatches |
        ForEach-Object { $_.Matches } | ForEach-Object { $names.Add($_.Groups[1].Value) }
    $names
}

function Get-DepsFromGoMod {
    param([string]$Text)
    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($line in ($Text -split "`n")) {
        $trimmed = $line.Trim()
        # "require module/path v1.2.3" or inside require ( ... ) blocks
        if ($trimmed -match '^([a-zA-Z0-9][a-zA-Z0-9\.\-_/]+)\s+v\d') {
            # Use only the last path segment for comparison
            $seg = $Matches[1] -split '/' | Select-Object -Last 1
            $names.Add($seg)
        }
    }
    $names
}

function Get-DepsFromCargoToml {
    param([string]$Text)
    $names = [System.Collections.Generic.List[string]]::new()
    $inDeps = $false
    foreach ($line in ($Text -split "`n")) {
        $trimmed = $line.Trim()
        if ($trimmed -match '^\[.*dependencies') { $inDeps = $true; continue }
        if ($trimmed.StartsWith('[') -and -not ($trimmed -match 'dependencies')) { $inDeps = $false }
        if ($inDeps -and $trimmed -match '^([a-zA-Z0-9][a-zA-Z0-9\-_]*)\s*=') {
            $names.Add($Matches[1])
        }
    }
    $names
}

function Get-DepsFromGemfile {
    param([string]$Text)
    $names = [System.Collections.Generic.List[string]]::new()
    foreach ($line in ($Text -split "`n")) {
        $trimmed = $line.Trim()
        if ($trimmed -match "^gem\s+['""]([A-Za-z0-9][A-Za-z0-9\-_\.]+)['""]") {
            $names.Add($Matches[1])
        }
    }
    $names
}

# ---------------------------------------------------------------------------
# Main scan body
# ---------------------------------------------------------------------------
$results = New-Object 'System.Collections.Generic.List[object]'

# Folder-level package identity
$folderPkgName    = ''
$folderPkgVersion = ''
$pkgJsonPath = Join-Path $ScanPath 'package.json'
if (Test-Path -LiteralPath $pkgJsonPath -PathType Leaf) {
    $pj = Get-JsonFile -Path $pkgJsonPath
    if ($pj) {
        $folderPkgName    = if ($pj.name)    { [string]$pj.name    } else { '' }
        $folderPkgVersion = if ($pj.version) { [string]$pj.version } else { '' }
    }
}

# Track which suspicious package names we've already flagged in this folder
# so we don't emit duplicate findings from lock files + manifests.
# We DO upgrade severity if the same name appears in both.
$seenPackages = @{}   # name → finding ref

foreach ($targetFile in $TargetFiles) {
    $filePath = Join-Path $ScanPath $targetFile
    if (-not (Test-Path -LiteralPath $filePath -PathType Leaf)) { continue }

    $text = Get-FileText -Path $filePath
    if ([string]::IsNullOrWhiteSpace($text)) { continue }

    # Extract dependency names based on file type
    $depNames = switch ($targetFile) {
        'package.json' {
            $obj = Get-JsonFile -Path $filePath
            if ($obj) { Get-NpmDepsFromJson -Obj $obj } else { @() }
        }
        { $_ -in 'package-lock.json','npm-shrinkwrap.json' } {
            $obj = Get-JsonFile -Path $filePath
            if ($obj) { Get-NpmDepsFromLockJson -Obj $obj } else { @() }
        }
        'yarn.lock'       { Get-DepsFromYarnLock      -Text $text }
        'pnpm-lock.yaml'  { Get-DepsFromPnpmLock      -Text $text }
        'requirements.txt'{ Get-DepsFromRequirementsTxt -Text $text }
        'pyproject.toml'  { Get-DepsFromPyprojectToml  -Text $text }
        'Pipfile'         { Get-DepsFromPipfile         -Text $text }
        { $_ -in 'setup.py','setup.cfg' } { Get-DepsFromSetupPy -Text $text }
        'go.mod'          { Get-DepsFromGoMod           -Text $text }
        'Cargo.toml'      { Get-DepsFromCargoToml       -Text $text }
        'Gemfile'         { Get-DepsFromGemfile          -Text $text }
        default           { @() }
    }

    foreach ($dep in ($depNames | Sort-Object -Unique)) {
        if ([string]::IsNullOrWhiteSpace($dep)) { continue }

        $assessment = Get-TyposquatAssessment -DepName $dep
        if (-not $assessment) { continue }

        $indicator = "Suspicious package '$dep'"
        if ($assessment.MatchedKnown) { $indicator += " (resembles '$($assessment.MatchedKnown)')" }
        $evidence  = ($assessment.Signals -join ' | ') + " [in $targetFile]"

        $rec = switch ($assessment.Severity) {
            'HIGH'   { "Investigate immediately — '$dep' may be a typosquat or dependency-confusion attack. Remove and verify the intended package." }
            'Medium' { "Manually verify '$dep' is the intended dependency and not a lookalike package." }
            default  { "Review '$dep' — weak typosquat signal, low confidence." }
        }

        if ($seenPackages.ContainsKey($dep)) {
            # Already reported — escalate to HIGH if seen in multiple files
            $existing = $seenPackages[$dep]
            if ($existing.Severity -ne 'HIGH') {
                $existing.Severity  = 'HIGH'
                $existing.Evidence += " | Also present in: $targetFile (multi-file escalation)"
            }
        } else {
            $finding = New-Finding `
                -Severity       $assessment.Severity `
                -Type           'TyposquatPackage' `
                -Path           $filePath `
                -PackageName    $folderPkgName `
                -Version        $folderPkgVersion `
                -Indicator      $indicator `
                -Evidence       $evidence `
                -Recommendation $rec

            $results.Add($finding)
            $seenPackages[$dep] = $finding
        }
    }
}

$results
