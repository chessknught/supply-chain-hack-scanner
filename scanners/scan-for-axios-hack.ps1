[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ScanPath,

    [ValidateSet('Quiet','Normal','Detailed','Debug')]
    [string]$VerbosityLevel = 'Detailed'
)

$ErrorActionPreference = 'SilentlyContinue'

$BadAxiosVersions = @('1.14.1', '0.30.4')
$BadPlainCryptoJsVersion = '4.2.1'
$SuspiciousDomains = @('sfrclak.com')

function Get-JsonFile {
    param([string]$Path)

    try {
        Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json -Depth 100
    }
    catch {
        $null
    }
}

function Get-FileText {
    param([string]$Path)

    try {
        Get-Content -LiteralPath $Path -Raw
    }
    catch {
        $null
    }
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

    $List.Add(
        (New-Finding `
            -Severity $Severity `
            -Type $Type `
            -Path $Path `
            -PackageName $PackageName `
            -Version $Version `
            -Indicator $Indicator `
            -Evidence $Evidence `
            -Recommendation $Recommendation)
    )
}

function Test-TextIndicators {
    param(
        [System.Collections.Generic.List[object]]$Findings,
        [string]$Text,
        [string]$Path,
        [string]$PackageName,
        [string]$Version
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return
    }

    foreach ($domain in $SuspiciousDomains) {
        if ($Text -match [regex]::Escape($domain)) {
            Add-Finding -List $Findings -Severity 'HIGH' -Type 'TextIndicator' -Path $Path -PackageName $PackageName -Version $Version -Indicator "Contains suspicious domain: $domain" -Evidence 'Matched text in file' -Recommendation 'Investigate immediately.'
        }
    }

    if ($Text -match '"postinstall"\s*:') {
        Add-Finding -List $Findings -Severity 'Medium' -Type 'TextIndicator' -Path $Path -PackageName $PackageName -Version $Version -Indicator 'Contains postinstall script' -Evidence 'Matched scripts.postinstall' -Recommendation 'Review whether this install-time script is expected.'
    }

    if ($Text -match 'plain-crypto-js') {
        Add-Finding -List $Findings -Severity 'HIGH' -Type 'TextIndicator' -Path $Path -PackageName $PackageName -Version $Version -Indicator 'References plain-crypto-js' -Evidence 'Matched package name text' -Recommendation 'Investigate immediately.'
    }

    if ($Text -match 'axios\s*"?\s*:\s*"?(1\.14\.1|0\.30\.4)') {
        Add-Finding -List $Findings -Severity 'HIGH' -Type 'TextIndicator' -Path $Path -PackageName $PackageName -Version $Version -Indicator 'References known malicious axios version' -Evidence 'Matched version text' -Recommendation 'Investigate immediately.'
    }
}

$results = New-Object 'System.Collections.Generic.List[object]'

try {
    $files = Get-ChildItem -LiteralPath $ScanPath -File -Force -ErrorAction Stop |
        Where-Object { $_.Name -in @('package.json', 'package-lock.json') }
}
catch {
    $files = @()
}

foreach ($file in $files) {
    $text = Get-FileText -Path $file.FullName
    $json = Get-JsonFile -Path $file.FullName

    if ($file.Name -eq 'package.json') {
        $pkgName = $null
        $pkgVersion = $null

        if ($json) {
            $pkgName = [string]$json.name
            $pkgVersion = [string]$json.version
        }

        Test-TextIndicators -Findings $results -Text $text -Path $file.FullName -PackageName $pkgName -Version $pkgVersion

        if ($json) {
            foreach ($sectionName in @('dependencies','devDependencies','optionalDependencies','peerDependencies')) {
                $section = $json.$sectionName
                if (-not $section) { continue }

                if ($section.PSObject.Properties.Name -contains 'axios') {
                    $declaredAxiosVersion = [string]$section.axios
                    $isBad = $declaredAxiosVersion -match '(^|[^\d])(1\.14\.1|0\.30\.4)([^\d]|$)'

                    Add-Finding -List $results -Severity $(if ($isBad) { 'HIGH' } else { 'Info' }) -Type 'DeclaredDependency' -Path $file.FullName -PackageName 'axios' -Version $declaredAxiosVersion -Indicator $(if ($isBad) { 'Declared known malicious axios version/range' } else { 'Declared axios dependency' }) -Evidence "package.json dependency: axios = $declaredAxiosVersion" -Recommendation $(if ($isBad) { 'Investigate immediately.' } else { 'Review if needed.' })
                }

                if ($section.PSObject.Properties.Name -contains 'plain-crypto-js') {
                    $declaredPlainVersion = [string]$section.'plain-crypto-js'
                    $isBad = $declaredPlainVersion -match '(^|[^\d])4\.2\.1([^\d]|$)'

                    Add-Finding -List $results -Severity $(if ($isBad) { 'HIGH' } else { 'Medium' }) -Type 'DeclaredDependency' -Path $file.FullName -PackageName 'plain-crypto-js' -Version $declaredPlainVersion -Indicator $(if ($isBad) { 'Declared malicious plain-crypto-js version/range' } else { 'Declared plain-crypto-js dependency' }) -Evidence "package.json dependency: plain-crypto-js = $declaredPlainVersion" -Recommendation 'Investigate immediately.'
                }
            }
        }
    }
    elseif ($file.Name -eq 'package-lock.json') {
        Test-TextIndicators -Findings $results -Text $text -Path $file.FullName -PackageName $null -Version $null

        if ($json -and ($json.PSObject.Properties.Name -contains 'packages')) {
            $packages = $json.packages

            if ($packages.PSObject.Properties.Name -contains 'node_modules/axios') {
                $v = [string]$packages.'node_modules/axios'.version
                $isBad = $BadAxiosVersions -contains $v

                Add-Finding -List $results -Severity $(if ($isBad) { 'HIGH' } else { 'Info' }) -Type 'LockfileDependency' -Path $file.FullName -PackageName 'axios' -Version $v -Indicator $(if ($isBad) { 'Lockfile includes known malicious axios version' } else { 'Lockfile includes axios' }) -Evidence "package-lock.json: axios@$v" -Recommendation $(if ($isBad) { 'Investigate immediately.' } else { 'Review if needed.' })
            }

            if ($packages.PSObject.Properties.Name -contains 'node_modules/plain-crypto-js') {
                $v = [string]$packages.'node_modules/plain-crypto-js'.version
                $isBad = $v -eq $BadPlainCryptoJsVersion

                Add-Finding -List $results -Severity $(if ($isBad) { 'HIGH' } else { 'Medium' }) -Type 'LockfileDependency' -Path $file.FullName -PackageName 'plain-crypto-js' -Version $v -Indicator $(if ($isBad) { 'Lockfile includes malicious plain-crypto-js version' } else { 'Lockfile includes plain-crypto-js' }) -Evidence "package-lock.json: plain-crypto-js@$v" -Recommendation 'Investigate immediately.'
            }
        }
    }
}

$results