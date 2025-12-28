# PowerShell script to add m140.dll to the release folder
# This script looks for MSVCR140.dll in common locations and copies it
# to the build/bin/Release directory, renaming it to m140.dll.

# Resolve the absolute path to the release directory relative to this script
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$releaseDir = Resolve-Path (Join-Path $scriptDir "../../build/bin/Release")
$target = Join-Path $releaseDir "m140.dll"

# Common locations for MSVCP140.dll (2022 runtime)
$searchPaths = @(
    "C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Redist\\MSVC\\14.44.35207\\x64",
    "C:\\Program Files (x86)\\Microsoft Visual Studio\\2022\\BuildTools\\VC\\Redist\\MSVC\\14.44.35207\\x86"
)

$found = $false
foreach ($path in $searchPaths) {
    $dll = Join-Path $path "MSVCP140.dll"
    if (Test-Path $dll) {
        Copy-Item -Path $dll -Destination $target -Force
        Write-Host "Copied MSVCP140.dll from $path to $target"
        $found = $true
        break
    }
}

if (-not $found) {
    Write-Warning "MSVCP140.dll not found in standard locations. Please install the Visual C++ 2022 Redistributable or provide the DLL manually."
}
