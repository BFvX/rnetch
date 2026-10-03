param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$metadata = Get-Content -LiteralPath (Join-Path $repoRoot 'deps/netfilter/SOURCE.json') -Raw | ConvertFrom-Json

# Obtain only the unmodified runtime used by the pinned Netch release. SDK
# headers and import libraries remain outside the source and release packages.
foreach ($entry in $metadata.files | Where-Object { $_.role -in @('runtime-library', 'runtime-driver') }) {
    $destination = Join-Path $repoRoot $entry.repository_path
    if (Test-Path -LiteralPath $destination -PathType Leaf) {
        if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ne $entry.sha256) {
            throw "Existing $($entry.repository_path) differs from the pinned runtime; refusing to replace it."
        }
        continue
    }
    $temporaryFile = "$destination.download"
    try {
        Invoke-WebRequest -Uri $entry.upstream_download -OutFile $temporaryFile -UseBasicParsing
        if ((Get-FileHash -LiteralPath $temporaryFile -Algorithm SHA256).Hash -ne $entry.sha256) {
            throw "Downloaded $($entry.repository_path) failed SHA-256 verification."
        }
        Move-Item -LiteralPath $temporaryFile -Destination $destination
    } finally {
        if (Test-Path -LiteralPath $temporaryFile) { Remove-Item -LiteralPath $temporaryFile -Force }
    }
}
Write-Host 'Pinned NetFilter runtime prepared. No driver was installed or started.'
