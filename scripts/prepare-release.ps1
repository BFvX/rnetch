param([string]$ReleaseTag = '')

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$package = Get-Content -LiteralPath (Join-Path $repoRoot 'ui/package.json') -Raw | ConvertFrom-Json
$version = [string]$package.version
$coreManifest = Get-Content -LiteralPath (Join-Path $repoRoot 'Cargo.toml') -Raw
if ($coreManifest -notmatch '(?m)^version\s*=\s*"([^"]+)"\s*$' -or $Matches[1] -ne $version) {
    throw 'Core and UI versions must match.'
}
if (-not $ReleaseTag) { $ReleaseTag = "v$version" }
if ($ReleaseTag -ne "v$version") { throw 'Release tag must match the core and UI version.' }

$assetDirectory = Join-Path $repoRoot 'build/release-assets'
$nativeStage = Join-Path $repoRoot 'build/package-resources/native'
$guiArchive = Join-Path $repoRoot "ui/release/Rnetch-Control-$version-win-x64-both.zip"
if (-not (Test-Path -LiteralPath $guiArchive -PathType Leaf)) { throw 'Build the both-backend portable package first.' }
New-Item -ItemType Directory -Path $assetDirectory -Force | Out-Null
$cliStage = Join-Path $repoRoot ('build/release-cli-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $cliStage | Out-Null

foreach ($name in @('rnetch.exe', 'nfapi.dll', 'nfdriver.sys', 'WinDivert.dll', 'WinDivert64.sys')) {
    $path = Join-Path $nativeStage $name
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Release runtime is missing: $name" }
    $pe = [IO.File]::ReadAllBytes($path)
    $offset = [BitConverter]::ToInt32($pe, 60)
    if ($offset -lt 64 -or $offset + 6 -gt $pe.Length -or [BitConverter]::ToUInt32($pe, $offset) -ne 0x4550 -or [BitConverter]::ToUInt16($pe, $offset + 4) -ne 0x8664) {
        throw "$name must be a Windows x64 PE file."
    }
}
foreach ($recordName in @('NetFilter-SOURCE.json', 'WinDivert-SOURCE.json')) {
    $record = Get-Content -LiteralPath (Join-Path $nativeStage $recordName) -Raw | ConvertFrom-Json
    foreach ($entry in $record.files) {
        $name = if ($recordName -eq 'NetFilter-SOURCE.json') {
            if ($entry.role -notin @('runtime-library', 'runtime-driver')) { continue }
            Split-Path $entry.repository_path -Leaf
        } else { $entry.name }
        if ((Get-FileHash -LiteralPath (Join-Path $nativeStage $name) -Algorithm SHA256).Hash -ne $entry.sha256) {
            throw "Release file differs from its provenance record: $name"
        }
    }
}
Copy-Item -Path (Join-Path $nativeStage '*') -Destination $cliStage -Recurse
Copy-Item -LiteralPath (Join-Path $repoRoot 'LICENSE') -Destination (Join-Path $cliStage 'LICENSE')
Copy-Item -LiteralPath (Join-Path $repoRoot 'THIRD_PARTY_NOTICES.md') -Destination $cliStage
Copy-Item -LiteralPath (Join-Path $repoRoot 'build/package-resources/config.xml') -Destination $cliStage
Copy-Item -LiteralPath (Join-Path $repoRoot 'config.gpux.example.xml') -Destination $cliStage
$instructions = @(
    "Rnetch $version - Windows x64 CLI",
    '',
    'Edit config.xml to configure your SOCKS5/GPUX endpoint and process rules.',
    'Validate without loading a driver: .\rnetch.exe .\config.xml --check-config',
    'Run from an administrator terminal: .\rnetch.exe .\config.xml',
    'Select another capture backend: .\rnetch.exe .\config.xml --backend windivert',
    'Press Enter or Ctrl+C to stop.',
    '',
    'Keep each DLL and its matching SYS file together.',
    'Project code: LICENSE. Third-party terms: THIRD_PARTY_NOTICES.md.',
    'NetFilter: NetFilter-NOTICE.txt and NetFilter-SOURCE.json.',
    'WinDivert: WinDivert-LICENSE, WinDivert-CORRESPONDING_SOURCE.json and the source ZIP.',
    'Dependency notices: licenses/INDEX.txt.',
    'https://github.com/BFvX/rnetch'
)
[IO.File]::WriteAllLines((Join-Path $cliStage 'README.txt'), $instructions, [Text.UTF8Encoding]::new($false))
[xml]$configuration = Get-Content -LiteralPath (Join-Path $cliStage 'config.xml') -Raw
if ($configuration.config.socks5.user -or $configuration.config.socks5.pass) { throw 'Release must not contain SOCKS5 credentials.' }
& (Join-Path $cliStage 'rnetch.exe') (Join-Path $cliStage 'config.xml') --check-config
if ($LASTEXITCODE -ne 0) { throw 'CLI package configuration check failed.' }

$assetNames = @("Rnetch-Control-$version-win-x64-both.zip", "rnetch-$version-win-x64-both.zip", "rnetch-source-$version.zip", 'WinDivert-2.2.2-source.zip')
Copy-Item -LiteralPath $guiArchive -Destination (Join-Path $assetDirectory $assetNames[0]) -Force
& (Join-Path $PSScriptRoot 'create-zip.ps1') -SourceDirectory $cliStage -DestinationPath (Join-Path $assetDirectory $assetNames[1])
Push-Location $repoRoot
try {
    git archive --format=zip "--output=$(Join-Path $assetDirectory $assetNames[2])" HEAD
    if ($LASTEXITCODE -ne 0) { throw 'Source archive creation failed.' }
} finally { Pop-Location }
Copy-Item -LiteralPath (Join-Path $nativeStage $assetNames[3]) -Destination (Join-Path $assetDirectory $assetNames[3]) -Force
$checksums = @($assetNames | ForEach-Object { "$((Get-FileHash -LiteralPath (Join-Path $assetDirectory $_) -Algorithm SHA256).Hash.ToLowerInvariant())  $_" })
[IO.File]::WriteAllLines((Join-Path $assetDirectory 'SHA256SUMS.txt'), $checksums, [Text.UTF8Encoding]::new($false))
Get-ChildItem -LiteralPath $assetDirectory -File | Select-Object Name, Length
