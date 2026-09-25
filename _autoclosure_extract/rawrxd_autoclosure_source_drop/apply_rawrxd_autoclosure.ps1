param(
    [string]$RepoRoot = "F:\~dev\rawrxd",
    [string]$DropRoot = $PSScriptRoot,
    [switch]$InstallOnly
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$marker = "RAWRXD_AUTOCLOSURE_001"
$src = Join-Path $DropRoot "src\closure"
$dst = Join-Path $RepoRoot "src\closure"
$cmake = Join-Path $RepoRoot "CMakeLists.txt"
$main = Join-Path $RepoRoot "src\win32app\main_win32.cpp"

if (-not (Test-Path $src)) { throw "Drop source missing: $src" }
if (-not (Test-Path $cmake)) { throw "CMakeLists.txt missing: $cmake" }

if (-not (Test-Path $main)) {
    $candidates = @(Get-ChildItem (Join-Path $RepoRoot "src") -Recurse -Filter main_win32.cpp -File -ErrorAction SilentlyContinue)
    if ($candidates.Count -ne 1) {
        throw "Expected exactly one main_win32.cpp, found $($candidates.Count). Refusing blind entrypoint patch."
    }
    $main = $candidates[0].FullName
}

# Prepare all edits in memory first. Nothing is modified until every assertion passes.
$cmakeText = [IO.File]::ReadAllText($cmake)
$mainText  = [IO.File]::ReadAllText($main)
$newCMake  = $cmakeText
$newMain   = $mainText

if (-not $cmakeText.Contains("# $marker")) {
    if (-not $cmakeText.Contains("RawrXD-Win32IDE")) {
        throw "RawrXD-Win32IDE target not found; refusing blind CMake edit."
    }
    $newCMake += @"

# RAWRXD_AUTOCLOSURE_001
target_sources(RawrXD-Win32IDE PRIVATE
    `${CMAKE_CURRENT_SOURCE_DIR}/src/closure/RawrXDAutoClosure.cpp
)
target_include_directories(RawrXD-Win32IDE PRIVATE
    `${CMAKE_CURRENT_SOURCE_DIR}/src
    `${CMAKE_CURRENT_SOURCE_DIR}/src/closure
)
"@
}

if (-not $mainText.Contains("closure/RawrXDAutoClosure.hpp")) {
    $newMain = "#include `"closure/RawrXDAutoClosure.hpp`"`r`n" + $newMain
}

if (-not $mainText.Contains("RawrXD::AutoClosure::CommandLineRequested()")) {
    $patterns = @(
        '(?s)(int\s+WINAPI\s+WinMain\s*\([^\)]*\)\s*\{)',
        '(?s)(int\s+APIENTRY\s+WinMain\s*\([^\)]*\)\s*\{)',
        '(?s)(int\s+WINAPI\s+wWinMain\s*\([^\)]*\)\s*\{)',
        '(?s)(int\s+APIENTRY\s+wWinMain\s*\([^\)]*\)\s*\{)'
    )
    $matched = $null
    foreach ($pat in $patterns) {
        $m = [regex]::Match($newMain, $pat)
        if ($m.Success) {
            if ($matched) { throw "Multiple WinMain-style entrypoints matched; refusing blind patch." }
            $matched = $m
        }
    }
    if (-not $matched) { throw "No WinMain/wWinMain entrypoint found in $main" }

    $hook = @'

    // RAWRXD_AUTOCLOSURE_001 — bounded autonomous CLI path before GUI startup.
    if (RawrXD::AutoClosure::CommandLineRequested()) {
        return RawrXD::AutoClosure::RunFromCurrentCommandLine();
    }
'@
    $newMain = $newMain.Substring(0, $matched.Index + $matched.Length) + $hook + $newMain.Substring($matched.Index + $matched.Length)
}

if ($InstallOnly) {
    New-Item -ItemType Directory -Force -Path $dst | Out-Null
    Copy-Item (Join-Path $src "RawrXDAutoClosure.hpp") $dst -Force
    Copy-Item (Join-Path $src "RawrXDAutoClosure.cpp") $dst -Force
    Write-Host "AUTOCLOSURE_SOURCE_INSTALLED=PASS"
    Write-Host "SOURCE_ONLY=1"
    exit 0
}

# Transaction-ish commit: backups first, then source + prepared text edits.
$stamp = Get-Date -Format "yyyyMMdd_HHmmss"
Copy-Item $cmake "$cmake.pre_autoclosure_$stamp.bak" -Force
Copy-Item $main  "$main.pre_autoclosure_$stamp.bak" -Force

New-Item -ItemType Directory -Force -Path $dst | Out-Null
Copy-Item (Join-Path $src "RawrXDAutoClosure.hpp") $dst -Force
Copy-Item (Join-Path $src "RawrXDAutoClosure.cpp") $dst -Force

$utf8 = [Text.UTF8Encoding]::new($false)
[IO.File]::WriteAllText($cmake, $newCMake, $utf8)
[IO.File]::WriteAllText($main,  $newMain,  $utf8)

# Post-write authority assertions.
$c2 = [IO.File]::ReadAllText($cmake)
$m2 = [IO.File]::ReadAllText($main)
if (-not $c2.Contains("src/closure/RawrXDAutoClosure.cpp")) { throw "CMake post-write assertion failed" }
if (-not $m2.Contains("closure/RawrXDAutoClosure.hpp")) { throw "include post-write assertion failed" }
if (-not $m2.Contains("RawrXD::AutoClosure::CommandLineRequested()")) { throw "WinMain hook post-write assertion failed" }

Write-Host "RAWRXD_AUTOCLOSURE_INSTALL=PASS"
Write-Host "SOURCE=$dst"
Write-Host "CMAKE=$cmake"
Write-Host "ENTRYPOINT=$main"
Write-Host "BACKUP_CMAKE=$cmake.pre_autoclosure_$stamp.bak"
Write-Host "BACKUP_MAIN=$main.pre_autoclosure_$stamp.bak"
Write-Host "NEXT=REBUILD_ONCE_THEN_USE_--autoclose"
