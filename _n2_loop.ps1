$parent = "9dc52741f1cead682030a4f4448629e71ca659be"
$stage = "F:\~dev\_n2_stage"
$master = "F:\~dev\_n2_master_missing.txt"
for ($cycle = 1; $cycle -le 8; $cycle++) {
  Write-Host "=== CYCLE $cycle ==="
  # 1. restore
  $fixed = 0
  foreach ($p in (Get-Content $master)) {
    if ($p -match "BuildStateGraph") { continue }
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
        $fixed++
      }
    }
    $stageDest = Join-Path $stage $p
    $sd = Split-Path $stageDest -Parent
    if (-not (Test-Path $sd)) { New-Item -ItemType Directory -Path $sd -Force | Out-Null }
    if (Test-Path $dest) { Copy-Item $dest $stageDest -Force }
  }
  Write-Host "CYCLE${cycle}_RESTORED=$fixed"
  # 2. configure, capture
  $out = cmake -S "F:\~dev\rawrxd" -B "F:\~dev\rawrxd\build_clean_n1" -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release -DRAWRXD_ALLOW_AGENTIC_STUB_FALLBACK=OFF -DRAWRXD_ENABLE_MISSING_HANDLER_STUBS=OFF -DRAWRXD_STRICT_AGENTIC_REALITY=ON -DRAWRXD_BUILD_LEGACY_CERTS=OFF -DRAWRXD_BUILD_WIN32IDE=ON 2>&1
  $out | Out-File "F:\~dev\_n2_loop_cfg.txt" -Encoding UTF8
  $failed = ($out | Select-String -SimpleMatch "Generate step failed").Count
  if ($failed -eq 0) {
    Write-Host "CONFIGURE=PASS"
    # 3. build
    $bout = cmake --build "F:\~dev\rawrxd\build_clean_n1" --config Release --target RawrXD-Win32IDE -j 2>&1
    
        Write-Host "BUILD_ATTEMPTED"
    $out | Out-File "F:\~dev\_n2_loop_build.txt" -Encoding UTF8
    break
  } else {
    # append newly missing to master
    $lines = Get-Content "F:\~dev\_n2_loop_cfg.txt"
    $idxs = ($lines | Select-String -SimpleMatch "Cannot find source file").LineNumber
    $new = foreach ($ix in $idxs) { $lines[$ix+1].Trim() -replace "F:/~dev/rawrxd/","" }
    $masterNow = Get-Content $master
    $merged = ($masterNow + $new) | Sort-Object -Unique
    $merged | Out-File $master -Encoding UTF8
    Write-Host "CONFIGURE=FAIL NEW_MISSING=$(@($new).Count) MASTER_NOW=$(@($merged).Count)"
  }
}

