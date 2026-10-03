param(
    [ValidateSet('both', 'netfilter', 'windivert')]
    [string]$Backend = 'both',
    [ValidateSet('zip', 'nsis')]
    [string]$Format = 'zip'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$uiDir = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$repoRoot = [System.IO.Path]::GetFullPath((Join-Path $uiDir '..'))
$stageRoot = Join-Path $repoRoot 'build\package-resources'
$nativeStage = Join-Path $stageRoot 'native'

# Default releases include both runtimes. A single-backend release requires an
# explicit -Backend argument so an incomplete package cannot claim both drivers.
& (Join-Path $repoRoot 'scripts\build.ps1') -Backend $Backend

$resolvedStageRoot = [System.IO.Path]::GetFullPath($stageRoot)
$expectedBuildRoot = [System.IO.Path]::GetFullPath((Join-Path $repoRoot 'build')).TrimEnd('\') + '\'
if (-not $resolvedStageRoot.StartsWith($expectedBuildRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Refusing to replace a package staging directory outside the workspace build directory.'
}
if (Test-Path -LiteralPath $resolvedStageRoot) {
    Remove-Item -LiteralPath $resolvedStageRoot -Recurse -Force
}
New-Item -ItemType Directory -Path $nativeStage -Force | Out-Null

$nativeFiles = @('rnetch.exe')
if ($Backend -in @('both', 'netfilter')) {
    $nativeFiles += @('nfapi.dll', 'nfdriver.sys')
    $nativeFiles += @('NetFilter-NOTICE.txt', 'NetFilter-SOURCE.json')
}
if ($Backend -in @('both', 'windivert')) {
    $nativeFiles += @('WinDivert.dll', 'WinDivert64.sys')
    $license = Join-Path $repoRoot 'deps\windivert\LICENSE'
    if (-not (Test-Path -LiteralPath $license -PathType Leaf)) {
        throw 'WinDivert LICENSE is required when distributing its runtime. Use scripts/setup-windivert.ps1.'
    }
    Copy-Item -LiteralPath $license -Destination (Join-Path $nativeStage 'WinDivert-LICENSE')
    foreach ($noticeName in @('README', 'VERSION', 'CHANGELOG')) {
        $noticePath = Join-Path $repoRoot "deps\windivert\$noticeName"
        if (Test-Path -LiteralPath $noticePath -PathType Leaf) {
            Copy-Item -LiteralPath $noticePath -Destination (Join-Path $nativeStage "WinDivert-$noticeName")
        }
    }
    $sourceMetadata = Join-Path $repoRoot 'deps\windivert\SOURCE.json'
    if (Test-Path -LiteralPath $sourceMetadata -PathType Leaf) {
        Copy-Item -LiteralPath $sourceMetadata -Destination (Join-Path $nativeStage 'WinDivert-SOURCE.json')
    }
    $sourceRecordPath = Join-Path $repoRoot 'deps/windivert/CORRESPONDING_SOURCE.json'
    $sourceRecord = Get-Content -LiteralPath $sourceRecordPath -Raw | ConvertFrom-Json
    $sourceCache = Join-Path $repoRoot 'build/windivert-download'
    New-Item -ItemType Directory -Path $sourceCache -Force | Out-Null
    $sourceArchive = Join-Path $sourceCache $sourceRecord.archive_name
    if (-not (Test-Path -LiteralPath $sourceArchive -PathType Leaf)) {
        Invoke-WebRequest -Uri $sourceRecord.download -OutFile $sourceArchive -UseBasicParsing
    }
    if ((Get-FileHash -LiteralPath $sourceArchive -Algorithm SHA256).Hash -ne $sourceRecord.sha256) {
        throw 'WinDivert corresponding-source archive failed SHA-256 verification.'
    }
    Copy-Item -LiteralPath $sourceArchive -Destination $nativeStage
    Copy-Item -LiteralPath $sourceRecordPath -Destination (Join-Path $nativeStage 'WinDivert-CORRESPONDING_SOURCE.json')
}
foreach ($name in $nativeFiles) {
    Copy-Item -LiteralPath (Join-Path $repoRoot "target\release\$name") -Destination $nativeStage
}
& (Join-Path $repoRoot 'scripts/collect-licenses.ps1') -OutputDirectory (Join-Path $nativeStage 'licenses')

# Package the public example so local endpoints and credentials never enter a
# release. Both-runtime releases preserve the example's backend preference.
[xml]$configDocument = Get-Content -LiteralPath (Join-Path $repoRoot 'config.example.xml') -Raw
$backendNode = $configDocument.SelectSingleNode('/config/backend')
if (-not $backendNode) {
    $backendNode = $configDocument.CreateElement('backend')
    [void]$configDocument.DocumentElement.PrependChild($backendNode)
    $backendNode.SetAttribute('type', 'netfilter')
}
if ($Backend -ne 'both') {
    $backendNode.SetAttribute('type', $Backend)
}
$packagedConfig = Join-Path $stageRoot 'config.xml'
$configDocument.Save($packagedConfig)
& (Join-Path $repoRoot 'target\release\rnetch.exe') $packagedConfig --check-config
if ($LASTEXITCODE -ne 0) { throw "Packaged configuration validation failed with exit code $LASTEXITCODE." }

Push-Location $uiDir
try {
    $package = Get-Content -LiteralPath 'package.json' -Raw | ConvertFrom-Json
    npm.cmd run build
    if ($LASTEXITCODE -ne 0) { throw "UI build failed with exit code $LASTEXITCODE." }

    if ($Format -eq 'nsis') {
        $artifactName = "Rnetch-Control-$($package.version)-win-x64-$Backend-setup.exe"
        npx.cmd --no-install electron-builder --win nsis --x64 "--config.artifactName=$artifactName"
        if ($LASTEXITCODE -ne 0) { throw "Installer packaging failed with exit code $LASTEXITCODE." }
        return
    }

    # A previous portable build may still be running from win-unpacked. Stage each
    # version separately so packaging never needs to stop the user's active app.
    $versionOutput = "release/$($package.version)-$Backend"
    npx.cmd --no-install electron-builder --win dir --x64 --config.win.signAndEditExecutable=false "--config.directories.output=$versionOutput"
    if ($LASTEXITCODE -ne 0) { throw "Electron packaging failed with exit code $LASTEXITCODE." }

    $appDir = (Resolve-Path -LiteralPath (Join-Path $versionOutput 'win-unpacked')).Path
    $exePath = Join-Path $appDir 'Rnetch Control.exe'
    $mt = Get-ChildItem -Path "${env:ProgramFiles(x86)}\Windows Kits\10\bin" -Recurse -Filter mt.exe -ErrorAction SilentlyContinue |
        Where-Object { $_.FullName -like '*\x64\mt.exe' } |
        Sort-Object FullName -Descending |
        Select-Object -First 1 -ExpandProperty FullName
    if (-not $mt) {
        throw 'mt.exe was not found. Install the Windows 10/11 SDK or run from a Visual Studio developer environment.'
    }

    $manifestPath = Join-Path $stageRoot 'rnetch-control.manifest.xml'
    & $mt -nologo "-inputresource:$exePath;#1" "-out:$manifestPath"
    if ($LASTEXITCODE -ne 0) { throw "Manifest extraction failed with exit code $LASTEXITCODE." }
    $manifest = Get-Content -LiteralPath $manifestPath -Raw
    if ($manifest -notmatch 'level="(?:asInvoker|requireAdministrator)"') {
        throw 'The Electron executable has an unexpected requested execution level.'
    }
    $manifest = $manifest -replace 'level="asInvoker"', 'level="requireAdministrator"'
    Set-Content -LiteralPath $manifestPath -Value $manifest -Encoding utf8
    & $mt -nologo -manifest $manifestPath "-outputresource:$exePath;#1"
    if ($LASTEXITCODE -ne 0) { throw "Manifest update failed with exit code $LASTEXITCODE." }
    Remove-Item -LiteralPath $manifestPath -Force

    # Use electron-builder's installed Windows-only resource editor. Its legacy
    # cross-platform winCodeSign archive contains macOS symlinks that cannot be
    # extracted on Windows without additional privileges.
    $iconEditor = Join-Path $uiDir 'node_modules/electron-winstaller/vendor/rcedit.exe'
    if (-not (Test-Path -LiteralPath $iconEditor -PathType Leaf)) {
        throw 'rcedit.exe was not found in electron-winstaller. Install the locked UI dependencies with npm ci.'
    }
    & $iconEditor $exePath --set-icon (Join-Path $uiDir 'assets/rnetch.ico')
    if ($LASTEXITCODE -ne 0) { throw "Executable icon update failed with exit code $LASTEXITCODE." }

    $zipPath = Join-Path (Resolve-Path -LiteralPath 'release').Path "Rnetch-Control-$($package.version)-win-x64-$Backend.zip"
    & (Join-Path $repoRoot 'scripts/create-zip.ps1') -SourceDirectory $appDir -DestinationPath $zipPath
    Write-Host "Created $zipPath (included backends: $Backend)"
} finally {
    Pop-Location
}
