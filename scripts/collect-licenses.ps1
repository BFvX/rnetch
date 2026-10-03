param([Parameter(Mandatory)][string]$OutputDirectory)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$OutputDirectory = [IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
$index = [Collections.Generic.List[string]]::new()

function Copy-PackageLicenses([string]$Kind, [string]$Name, [string]$Version, [string]$License, [string]$Directory) {
    $files = @(Get-ChildItem -LiteralPath $Directory -File | Where-Object { $_.Name -match '(?i)^(license|copying|notice)' })
    if ($files.Count -eq 0) { throw "No license text found for $Kind dependency $Name $Version." }
    $relativeDirectory = "$Kind/$($Name -replace '[/\\]', '_')-$Version"
    $destination = Join-Path $OutputDirectory $relativeDirectory
    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    foreach ($file in $files) { Copy-Item -LiteralPath $file.FullName -Destination $destination -Force }
    $index.Add("$Kind | $Name | $Version | $License | $relativeDirectory")
}

Push-Location $repoRoot
try {
    $rawMetadata = cargo metadata --locked --offline --filter-platform x86_64-pc-windows-msvc --format-version 1
    if ($LASTEXITCODE -ne 0) { throw 'Cargo license metadata could not be read.' }
    $metadata = $rawMetadata | ConvertFrom-Json
    $resolvedIds = @($metadata.resolve.nodes | ForEach-Object { $_.id })
    foreach ($package in $metadata.packages | Where-Object { $_.source -and $_.id -in $resolvedIds } | Sort-Object name) {
        Copy-PackageLicenses 'cargo' $package.name $package.version $package.license (Split-Path $package.manifest_path)
    }
    Push-Location (Join-Path $repoRoot 'ui')
    try {
        $dependencyPaths = @(npm.cmd ls --omit=dev --all --parseable)
        if ($LASTEXITCODE -ne 0) { throw 'Installed production npm dependencies could not be listed.' }
        foreach ($directory in $dependencyPaths | Select-Object -Skip 1 | Sort-Object -Unique) {
            $package = Get-Content -LiteralPath (Join-Path $directory 'package.json') -Raw | ConvertFrom-Json
            Copy-PackageLicenses 'npm' $package.name $package.version ([string]$package.license) $directory
        }
    } finally { Pop-Location }
} finally { Pop-Location }
[IO.File]::WriteAllLines((Join-Path $OutputDirectory 'INDEX.txt'), $index, [Text.UTF8Encoding]::new($false))
Write-Host "Collected $($index.Count) dependency license notices."
