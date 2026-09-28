$parent = "9dc52741f1cead682030a4f4448629e71ca659be"
$master = "F:\~dev\_n2_master_missing.txt"
$masterLines = Get-Content $master
$headRefs = Get-Content "F:\~dev\_n2_head_sources.txt" | Select-Object -Skip 1
$allRefs = ($masterLines + $headRefs) | Sort-Object -Unique
for ($attempt = 1; $attempt -le 6; $attempt++) {
    Write-Host "=== ATTEMPT $attempt ==="
    $restored = 0
    foreach ($p in $allRefs) {
        if (-not $p -or $p -match "BuildStateGraph") { continue }
        $dest = "F:\~dev\rawrxd\$p"
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
    Write-Host "ATTEMPT${attempt}_RESTORED=$restored"
    New-Item -ItemType Directory -Path "F:\~dev\rawrxd\build_clean_n1\RawrXD-Win32IDE.dir\Release\src\asm" -Force -ErrorAction SilentlyContinue | Out-Null
    New-Item -ItemType Directory -Path "F:\~dev\rawrxd\build_clean_n1\InferenceEngine.dir\Release\src\asm" -Force -ErrorAction SilentlyContinue | Out-Null
    $out = cmake -S "F:\~dev\rawrxd" -B "F:\~dev\rawrxd\build_clean_n1" -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release -DRAWRXD_ALLOW_AGENTIC_STUB_FALLBACK=OFF -DRAWRXD_ENABLE_MISSING_HANDLER_STUBS=OFF -DRAWRXD_STRICT_AGENTIC_REALITY=ON -DRAWRXD_BUILD_LEGACY_CERTS=OFF -DRAWRXD_BUILD_WIN32IDE=ON 2>&1
    $out | Out-File "F:\~dev\_n2_final_cfg.txt" -Encoding UTF8
    $failed = ($out | Select-String -SimpleMatch "Generate step failed").Count
    if ($failed -eq 0) {
        Write-Host "CONFIGURE=PASS"
        $bout = cmake --build "F:\~dev\rawrxd\build_clean_n1" --config Release --target RawrXD-Win32IDE -j 2>&1
        $bout | Out-File "F:\~dev\_n2_final_build.txt" -Encoding UTF8
        $exe = Test-Path "F:\~dev\rawrxd\build_clean_n1\bin\Release\RawrXD-Win32IDE.exe"
        Write-Host "BUILD_DONE EXE=$exe"
        if ($exe) { Write-Host "N2_SUCCESS"; break }
    } else {
        Write-Host "CONFIGURE=FAIL"
    }
}