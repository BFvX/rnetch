param()

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../../..'))
$sourceRoot = Join-Path $repoRoot 'legacy/cpp/src'
$sdkHeaders = Join-Path $repoRoot 'deps/netfilter/include'
$output = Join-Path $repoRoot 'build/legacy-cpp-tests'

# This only builds mock/loopback tests. It never links nfapi.dll; service calls
# are mocked. It does not load drivers, touch services, or build the old product.
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
if (-not (Test-Path -LiteralPath $vswhere)) { throw 'Visual Studio Build Tools are required.' }
$vsInstall = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $vsInstall) { throw 'MSVC x64 tools are required.' }
Import-Module (Join-Path $vsInstall 'Common7/Tools/Microsoft.VisualStudio.DevShell.dll')
Enter-VsDevShell -VsInstallPath $vsInstall -SkipAutomaticLocation -DevCmdArguments '-arch=x64 -host_arch=x64' | Out-Null
New-Item -ItemType Directory -Path $output -Force | Out-Null

$publicHeaders = Join-Path $repoRoot 'legacy/cpp/include'
$flags = @('/nologo', '/std:c++17', '/EHsc', '/W4', '/WX', '/O2', '/utf-8', "/I$sdkHeaders", "/I$sourceRoot", "/I$publicHeaders")
Push-Location $output
try {
    foreach ($source in @('rnetch', 'socks5', 'tcp_relay', 'udp_relay', 'proxy_process', 'driver', 'main')) {
        & cl.exe @flags /c (Join-Path $sourceRoot "$source.cpp") "/Fo:$source-check.obj"
        if ($LASTEXITCODE -ne 0) { throw "C++ source check failed: $source" }
    }

    $tests = @(
        @{ Name = 'tcp_relay'; Sources = @('tcp_relay.cpp'); Defines = @() },
        @{ Name = 'socks5'; Sources = @('socks5.cpp', 'proxy_process.cpp'); Defines = @() },
        # This test includes udp_relay.cpp to exercise its private frame/cache code.
        @{ Name = 'udp_relay'; Sources = @('socks5.cpp', 'proxy_process.cpp'); Defines = @() },
        @{ Name = 'proxy_process'; Sources = @('proxy_process.cpp'); Defines = @() },
        # The ownership test includes driver.cpp behind mocked SCM function calls.
        @{ Name = 'driver_ownership'; Sources = @(); Defines = @() },
        @{ Name = 'netfilter_callbacks'; Sources = @('socks5.cpp', 'tcp_relay.cpp', 'udp_relay.cpp', 'proxy_process.cpp'); Defines = @('/D_NFAPI_STATIC_LIB=') }
    )
    $failures = @()
    foreach ($test in $tests) {
        $name = $test.Name
        $testSource = Join-Path $PSScriptRoot "$($name)_test.cpp"
        $sources = @($testSource) + @($test.Sources | ForEach-Object { Join-Path $sourceRoot $_ })
        $defines = $test.Defines
        $exe = Join-Path $output "$($name)_test.exe"
        & cl.exe @flags @defines @sources "/Fe:$exe" /link ws2_32.lib iphlpapi.lib advapi32.lib
        if ($LASTEXITCODE -ne 0) {
            $failures += "$name (build)"
            continue
        }
        $stdout = Join-Path $output "$name.stdout.log"
        $stderr = Join-Path $output "$name.stderr.log"
        $process = Start-Process -FilePath $exe -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
        # Retain the process handle so Windows PowerShell can read ExitCode even
        # when a short test exits before WaitForExit starts.
        $processHandle = $process.Handle
        if (-not $process.WaitForExit(60000)) {
            $process.Kill()
            $failures += "$name (60-second timeout)"
            continue
        }
        $process.WaitForExit()
        Get-Content -LiteralPath $stdout
        if ($process.ExitCode -ne 0) {
            Get-Content -LiteralPath $stderr
            $failures += "$name (exit $($process.ExitCode))"
        }
    }
    if ($failures.Count) { throw "C++ regression suites failed: $($failures -join ', '). See $output for logs." }
    Write-Host 'All archived C++ regression suites passed without loading a driver.'
} finally {
    Pop-Location
}
