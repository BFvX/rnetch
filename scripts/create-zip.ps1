param(
    [Parameter(Mandatory)][string]$SourceDirectory,
    [Parameter(Mandatory)][string]$DestinationPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
Add-Type -AssemblyName System.IO.Compression
$sourceRoot = (Resolve-Path -LiteralPath $SourceDirectory).Path.TrimEnd('\', '/')
$destination = [IO.Path]::GetFullPath($DestinationPath)
$output = [IO.File]::Open($destination, [IO.FileMode]::Create, [IO.FileAccess]::Write)
try {
    $archive = [IO.Compression.ZipArchive]::new($output, [IO.Compression.ZipArchiveMode]::Create, $true)
    try {
        foreach ($file in Get-ChildItem -LiteralPath $sourceRoot -Recurse -File -Force | Sort-Object FullName) {
            $name = $file.FullName.Substring($sourceRoot.Length + 1).Replace('\', '/')
            $entry = $archive.CreateEntry($name, [IO.Compression.CompressionLevel]::Optimal)
            # Reproducible npm packages may carry 1970 timestamps; ZIP supports
            # only 1980..2107. Normalize archive metadata, not the input files.
            $timestamp = $file.LastWriteTime
            if ($timestamp.Year -lt 1980 -or $timestamp.Year -gt 2107) { $timestamp = [datetime]'1980-01-01T00:00:00' }
            $entry.LastWriteTime = [DateTimeOffset]$timestamp
            $input = [IO.File]::OpenRead($file.FullName)
            $entryStream = $entry.Open()
            try { $input.CopyTo($entryStream) } finally { $entryStream.Dispose(); $input.Dispose() }
        }
    } finally { $archive.Dispose() }
} finally { $output.Dispose() }
