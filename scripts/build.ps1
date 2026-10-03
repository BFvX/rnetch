param(
    [ValidateSet('auto', 'netfilter', 'windivert', 'both')]
    [string]$Backend = 'auto'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$releaseDir = Join-Path $repoRoot 'target\release'
$runtimeFiles = @()

if ($Backend -in @('auto', 'netfilter', 'both')) {
    $runtimeFiles += @('deps\nfapi.dll', 'deps\nfdriver.sys')
}

$windivertFiles = @('deps\windivert\WinDivert.dll', 'deps\windivert\WinDivert64.sys')
$windivertCount = @($windivertFiles | Where-Object { Test-Path -LiteralPath (Join-Path $repoRoot $_) -PathType Leaf }).Count
if ($Backend -in @('windivert', 'both') -or ($Backend -eq 'auto' -and $windivertCount -gt 0)) {
    $runtimeFiles += $windivertFiles
}

foreach ($relativePath in $runtimeFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $repoRoot $relativePath) -PathType Leaf)) {
        throw "Required runtime file is missing: $relativePath. For WinDivert, run scripts/setup-windivert.ps1."
    }
}

Push-Location $repoRoot
try {
    # Pin the output location used by the Electron development launcher.
    cargo build --release --locked --target-dir (Join-Path $repoRoot 'target')
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed with exit code $LASTEXITCODE." }

    $executable = Join-Path $releaseDir 'rnetch.exe'
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) {
        throw "Expected $executable. Use the x86_64-pc-windows-msvc host toolchain without CARGO_BUILD_TARGET overrides."
    }
    $pe = [System.IO.File]::ReadAllBytes($executable)
    if ($pe.Length -lt 64) { throw 'Native executable is not a valid PE file.' }
    $peOffset = [BitConverter]::ToInt32($pe, 60)
    if ($peOffset -lt 64 -or $peOffset + 6 -gt $pe.Length -or [BitConverter]::ToUInt32($pe, $peOffset) -ne 0x00004550 -or [BitConverter]::ToUInt16($pe, $peOffset + 4) -ne 0x8664) {
        throw 'Native executable must be Windows x64 (PE AMD64). Use the x86_64-pc-windows-msvc toolchain.'
    }

    foreach ($relativePath in $runtimeFiles) {
        Copy-Item -LiteralPath (Join-Path $repoRoot $relativePath) -Destination $releaseDir -Force
    }
    Copy-Item -LiteralPath (Join-Path $repoRoot 'LICENSE') -Destination (Join-Path $releaseDir 'rnetch-LICENSE') -Force
    Copy-Item -LiteralPath (Join-Path $repoRoot 'THIRD_PARTY_NOTICES.md') -Destination $releaseDir -Force
    if ($runtimeFiles -contains 'deps\nfapi.dll') {
        Copy-Item -LiteralPath (Join-Path $repoRoot 'deps/netfilter/NOTICE.txt') -Destination (Join-Path $releaseDir 'NetFilter-NOTICE.txt') -Force
        Copy-Item -LiteralPath (Join-Path $repoRoot 'deps/netfilter/SOURCE.json') -Destination (Join-Path $releaseDir 'NetFilter-SOURCE.json') -Force
    }
    if ($runtimeFiles -contains 'deps\windivert\WinDivert.dll') {
        foreach ($noticeName in @('LICENSE', 'README', 'VERSION', 'CHANGELOG', 'SOURCE.json')) {
            $noticePath = Join-Path $repoRoot "deps\windivert\$noticeName"
            if (Test-Path -LiteralPath $noticePath -PathType Leaf) {
                Copy-Item -LiteralPath $noticePath -Destination (Join-Path $releaseDir "WinDivert-$noticeName") -Force
            }
        }
    }
    Write-Host "Built $(Join-Path $releaseDir 'rnetch.exe')"
    if ($Backend -eq 'auto' -and $windivertCount -eq 0) {
        Write-Host 'NetFilter runtime copied. WinDivert runtime is not installed; use setup-windivert.ps1 before selecting WinDivert.'
    } else {
        Write-Host "Copied runtime files for backend selection: $Backend"
    }
} finally {
    Pop-Location
}
