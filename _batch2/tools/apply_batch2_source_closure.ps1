param(
    [string]$Repo = "F:\~dev\rawrxd"
)

$ErrorActionPreference = "Stop"
$Repo = (Resolve-Path $Repo).Path
$cmake = Join-Path $Repo "CMakeLists.txt"
$fragmentSrc = Join-Path $PSScriptRoot "..\cmake\RawrXDStrictWin32IDESourceClosure.cmake"
$fragmentDstDir = Join-Path $Repo "cmake"
$fragmentDst = Join-Path $fragmentDstDir "RawrXDStrictWin32IDESourceClosure.cmake"

if (!(Test-Path $cmake)) { throw "CMakeLists.txt not found: $cmake" }
New-Item -ItemType Directory -Force -Path $fragmentDstDir | Out-Null
Copy-Item -Force $fragmentSrc $fragmentDst

$text = Get-Content $cmake -Raw
$needle = 'add_executable(RawrXD-Win32IDE WIN32 ${WIN32IDE_SOURCES} ${_WIN32IDE_ASM} ${WIN32IDE_EXTRA_ASM})'
$include = 'include(cmake/RawrXDStrictWin32IDESourceClosure.cmake)'

if ($text -notmatch [regex]::Escape($needle)) {
    throw "Expected RawrXD-Win32IDE add_executable signature not found. Refusing blind patch."
}

if ($text -notmatch [regex]::Escape($include)) {
    $backup = "$cmake.batch2.bak"
    Copy-Item -Force $cmake $backup
    $replacement = "$include`r`n    $needle"
    $text = $text.Replace($needle, $replacement)
    Set-Content -Path $cmake -Value $text -Encoding UTF8
    Write-Host "Patched: $cmake"
    Write-Host "Backup : $backup"
} else {
    Write-Host "Strict closure already included; no CMake patch needed."
}

Write-Host "Installed: $fragmentDst"
