param(
    [ValidatePattern('^[A-Fa-f0-9]{64}$')]
    [string]$ArchiveSha256,
    [string]$ArchivePath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# An optional expected SHA-256 may be provided from a separately trusted source.
# Otherwise use a published GitHub asset digest when available, HTTPS provenance,
# and Windows verification of the driver's Authenticode signature. A recorded
# download hash is a reproducibility record, not an independent official checksum.
$version = '2.2.2'
$releaseUrl = "https://github.com/basil00/WinDivert/releases/tag/v$version"
$downloadUrl = "https://github.com/basil00/WinDivert/releases/download/v$version/WinDivert-$version-A.zip"
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$cacheRoot = Join-Path $repoRoot 'build\windivert-download'
$workDir = Join-Path $cacheRoot ([Guid]::NewGuid().ToString('N'))
$destination = Join-Path $repoRoot 'deps\windivert'
New-Item -ItemType Directory -Path $workDir -Force | Out-Null

try {
    if ($ArchivePath) {
        $archive = (Resolve-Path -LiteralPath $ArchivePath).Path
        $origin = 'caller-supplied-local-archive'
    } else {
        $origin = 'official-github-release-https'
        $metadata = Invoke-RestMethod -Uri "https://api.github.com/repos/basil00/WinDivert/releases/tags/v$version" -Headers @{ 'User-Agent' = 'rnetch-setup' }
        $asset = @($metadata.assets | Where-Object { $_.name -eq "WinDivert-$version-A.zip" })
        if ($asset.Count -ne 1 -or $asset[0].browser_download_url -ne $downloadUrl) {
            throw 'Official release metadata did not contain the expected pinned WinDivert archive URL.'
        }
        $publishedDigest = if ($asset[0].PSObject.Properties['digest']) { [string]$asset[0].digest } else { '' }
        $archive = Join-Path $workDir "WinDivert-$version-A.zip"
        Invoke-WebRequest -Uri $downloadUrl -OutFile $archive -UseBasicParsing
    }

    $actualHash = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
    if ($ArchiveSha256 -and $actualHash -ne $ArchiveSha256) {
        throw "SHA-256 mismatch for WinDivert $version. No runtime files were copied."
    }
    $hashVerification = if ($ArchiveSha256) { 'caller-supplied-expected-sha256' } else { 'no-independent-checksum-published; HTTPS source and driver Authenticode verified' }
    if (-not $ArchivePath -and $publishedDigest -match '^sha256:([A-Fa-f0-9]{64})$') {
        if ($actualHash -ne $Matches[1]) {
            throw 'Archive SHA-256 does not match the digest published by GitHub.'
        }
        $hashVerification = 'github-release-asset-sha256'
    } elseif ($ArchivePath -and -not $ArchiveSha256) {
        $hashVerification = 'no-independent-checksum; local archive supplied by caller; driver Authenticode verified'
    }

    $extractDir = Join-Path $workDir 'unpacked'
    Expand-Archive -LiteralPath $archive -DestinationPath $extractDir
    $sdkRoot = Join-Path $extractDir "WinDivert-$version-A"
    $requiredFiles = @('x64\WinDivert.dll', 'x64\WinDivert64.sys', 'LICENSE', 'README', 'VERSION', 'CHANGELOG')
    foreach ($relativePath in $requiredFiles) {
        if (-not (Test-Path -LiteralPath (Join-Path $sdkRoot $relativePath) -PathType Leaf)) {
            throw "The verified archive does not contain expected WinDivert $version file: $relativePath"
        }
    }

    $driverSignature = Get-AuthenticodeSignature -LiteralPath (Join-Path $sdkRoot 'x64\WinDivert64.sys')
    if ($driverSignature.Status -ne 'Valid') {
        throw "WinDivert driver signature verification failed: $($driverSignature.StatusMessage). No runtime files were copied."
    }

    New-Item -ItemType Directory -Path $destination -Force | Out-Null
    foreach ($relativePath in $requiredFiles) {
        Copy-Item -LiteralPath (Join-Path $sdkRoot $relativePath) -Destination $destination -Force
    }
    [ordered]@{
        version = $version
        architecture = 'x64'
        origin = $origin
        release = $releaseUrl
        download = $downloadUrl
        archive_sha256 = $actualHash.ToLowerInvariant()
        checksum_verification = $hashVerification
        driver_signature = @{
            status = [string]$driverSignature.Status
            subject = $driverSignature.SignerCertificate.Subject
            thumbprint = $driverSignature.SignerCertificate.Thumbprint
            timestamp_subject = if ($driverSignature.TimeStamperCertificate) { $driverSignature.TimeStamperCertificate.Subject } else { $null }
        }
        files = @(
            @{ name = 'WinDivert.dll'; sha256 = (Get-FileHash -LiteralPath (Join-Path $destination 'WinDivert.dll') -Algorithm SHA256).Hash.ToLowerInvariant() },
            @{ name = 'WinDivert64.sys'; sha256 = (Get-FileHash -LiteralPath (Join-Path $destination 'WinDivert64.sys') -Algorithm SHA256).Hash.ToLowerInvariant() }
        )
    } | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $destination 'SOURCE.json') -Encoding UTF8
    Write-Host "Verified WinDivert $version x64 runtime copied to $destination. No driver was installed or started."
} finally {
    $resolvedWorkDir = [System.IO.Path]::GetFullPath($workDir)
    $resolvedCacheRoot = [System.IO.Path]::GetFullPath($cacheRoot).TrimEnd('\') + '\'
    if (-not $resolvedWorkDir.StartsWith($resolvedCacheRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw 'Refusing to clean up a download directory outside the workspace cache.'
    }
    Remove-Item -LiteralPath $resolvedWorkDir -Recurse -Force
}
