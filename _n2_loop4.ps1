$ErrorActionPreference = "Continue"
$parent = "9dc52741f1cead682030a4f4448629e71ca659be"
$repo = "F:\~dev\rawrxd"
$build = "F:\~dev\rawrxd\build_clean_n1"

# Build the complete restore list: master + head refs + k2 tests + every tests/*.cpp referenced in HEAD CMakeLists
$master = Get-Content "F:\~dev\_n2_master_missing.txt" -ErrorAction SilentlyContinue
$headRefs = Get-Content "F:\~dev\_n2_head_sources.txt" | Select-Object -Skip 1
$headText = git show "HEAD:rawrxd/CMakeLists.txt"
$testRefs = ($headText -split "`n") | Select-String -Pattern "tests/[A-Za-z0-9_/\.\-]+\.cpp" -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique
$allRefs = ($master + $headRefs + $testRefs) | Where-Object { $_ -and $_ -notmatch "BuildStateGraph" } | Sort-Object -Unique
"TOTAL_REFS=$(@($allRefs).Count)"

function Restore-All {
    $restored = 0
    foreach ($p in $allRefs) {
        $dest = Join-Path $repo ($p -replace "/", "\")
        if (-not (Test-Path $dest)) {
            $content = git show "$($parent):rawrxd/$p" 2>$null
            if ($LASTEXITCODE -eq 0) {
                $joined = $content -join "`n"
                if ($joined -match "(/[/!].*|#include.*)") { $code = $Matches[1] } else { $code = $joined }
                $code = ($code -replace "[^\x20-\x7E\r\n]", "").Trim()
                $destDir = Split-Path $dest -Parent
                if (-not (Test-Path $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }
                [System.IO.File]::WriteAllText($dest, $code + "`r`n", [System.Text.Encoding]::ASCII)
                $restored++
            }
        }
    }
    return $restored
}

for ($attempt = 1; $attempt -le 10; $attempt++) {
    Write-Host "=== ATTEMPT $attempt ==="

    # 1. Revert CMakeLists to HEAD (clean, 0 AUTO-REMOVED)
    git -C $repo checkout HEAD -- CMakeLists.txt
    $ar = (Select-String -Path (Join-Path $repo "CMakeLists.txt") -Pattern "AUTO-REMOVED").Count
    Write-Host "AR=$ar"
    if ($ar -ne 0) { Write-Host "CMAKE_REVERT_FAILED"; continue }

    # 2. Restore all files
    $r = Restore-All
    Write-Host "RESTORED=$r"

    # 3. Pre-create ml64 output dirs
    New-Item -ItemType Directory -Path "$build\RawrXD-Win32IDE.dir\Release\src\asm" -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item -ItemType Directory -Path "$build\RawrXD-Win32IDE.dir\Release\src\deep2\lavapath" -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item -ItemType Directory -Path "$build\InferenceEngine.dir\Release\src\asm" -Force -ErrorAction SilentlyContinue | Out-Null

    # 4. Configure
    $cfg = cmake -S $repo -B $build -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release -DRAWRXD_ALLOW_AGENTIC_STUB_FALLBACK=OFF -DRAWRXD_ENABLE_MISSING_HANDLER_STUBS=OFF -DRAWRXD_STRICT_AGENTIC_REALITY=ON -DRAWRXD_BUILD_LEGACY_CERTS=OFF -DRAWRXD_BUILD_WIN32IDE=ON 2>&1
    $cfg | Out-File "F:\~dev\_n2_final_cfg.txt" -Encoding UTF8
    $cfgErrs = ($cfg | Select-String -SimpleMatch "CMake Error").Count
    Write-Host "CFG_ERRS=$cfgErrs"
    if ($cfgErrs -ne 0) {
        # log missing files for diagnosis
        $miss = $cfg | Select-String -SimpleMatch "Cannot find source file" | Select-Object -First 30
        $miss | Out-File "F:\~dev\_n2_cfg_miss.txt" -Encoding UTF8
        continue
    }

    # 5. Build
    $bout = cmake --build $build --config Release --target RawrXD-Win32IDE -j 2>&1
    $bout | Out-File "F:\~dev\_n2_final_build.txt" -Encoding UTF8
    $berrs = @($bout | Select-String -SimpleMatch ": error ").Count
    $exe = Test-Path "$build\bin\Release\RawrXD-Win32IDE.exe"
    $unres = @($bout | Select-String -SimpleMatch "unresolved").Count
    Write-Host "BUILD_ERRS=$berrs UNRES=$unres EXE=$exe"

    if ($exe) {
        Write-Host "N2_SUCCESS"
        # dumpbin unresolved check
        $dumpbin = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe"
        & $dumpbin /DEPENDENTS "$build\bin\Release\RawrXD-Win32IDE.exe" 2>&1 | Out-File "F:\~dev\_n2_ide_dependents.txt" -Encoding UTF8
        break
    }

    # 6. If build failed with C1083, extract and log victims (Restore-All next attempt will fix)
    $c1083 = $bout | Select-String -SimpleMatch ": error C1083" | Select-Object -First 60
    $c1083 | Out-File "F:\~dev\_n2_build_miss.txt" -Encoding UTF8
}