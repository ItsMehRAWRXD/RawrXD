$parent = "9dc52741f1cead682030a4f4448629e71ca659be"
$master = "F:\~dev\_n2_master_missing.txt"
$overall = 0
for ($buildAttempt = 1; $buildAttempt -le 6; $buildAttempt++) {
  Write-Host "=== BUILD_ATTEMPT $buildAttempt ==="
  # configure loop (restore until configure passes)
  $configured = $false
  for ($cycle = 1; $cycle -le 8; $cycle++) {
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
    }
    if ($fixed -gt 0) { Write-Host "ATTEMPT${buildAttempt}_CYCLE${cycle}_RESTORED=$fixed" }
    # pre-create asm dirs
    New-Item -ItemType Directory -Path "F:\~dev\rawrxd\build_clean_n1\RawrXD-Win32IDE.dir\Release\src\asm" -Force -ErrorAction SilentlyContinue | Out-Null
    $out = cmake -S "F:\~dev\rawrxd" -B "F:\~dev\rawrxd\build_clean_n1" -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release -DRAWRXD_ALLOW_AGENTIC_STUB_FALLBACK=OFF -DRAWRXD_ENABLE_MISSING_HANDLER_STUBS=OFF -DRAWRXD_STRICT_AGENTIC_REALITY=ON -DRAWRXD_BUILD_LEGACY_CERTS=OFF -DRAWRXD_BUILD_WIN32IDE=ON 2>&1
    $out | Out-File "F:\~dev\_n2_loop_cfg.txt" -Encoding UTF8
    $failed = ($out | Select-String -SimpleMatch "Generate step failed").Count
    if ($failed -eq 0) { Write-Host "CONFIGURE=PASS (cycle $cycle)"; $configured = $true; break }
    # merge newly missing
    $lines = Get-Content "F:\~dev\_n2_loop_cfg.txt"
    $idxs = ($lines | Select-String -SimpleMatch "Cannot find source file").LineNumber
    $new = foreach ($ix in $idxs) { $lines[$ix+1].Trim() -replace "F:/~dev/rawrxd/","" }
    if (@($new).Count -gt 0) {
      $merged = ((Get-Content $master) + $new) | Sort-Object -Unique
      $merged | Out-File $master -Encoding UTF8
      Write-Host "CONFIGURE=FAIL NEW=$(@($new).Count) MASTER=$(@($merged).Count)"
    } else { Write-Host "CONFIGURE=FAIL (unknown cause)"; break }
  }
  if (-not $configured) { Write-Host "GIVING_UP_CONFIGURE attempt $buildAttempt"; continue }
  # BUILD
  $bout = cmake --build "F:\~dev\rawrxd\build_clean_n1" --config Release --target RawrXD-Win32IDE -j 2>&1
  $bout | Out-File "F:\~dev\_n2_build_attempt${buildAttempt}.txt" -Encoding UTF8
  $lnkFail = ($bout | Select-String -SimpleMatch "LNK").Count
  $c1083 = ($bout | Select-String -SimpleMatch "C1083").Count
  $exeCheck = Test-Path "F:\~dev\rawrxd\build_clean_n1\bin\Release\RawrXD-Win32IDE.exe"
  Write-Host "BUILD_DONE exe=$exeCheck lnk_lines=$lnkFail c1083=$c1083"
  if ($exeCheck) { Write-Host "IDE_EXE_EXISTS=1"; break }
}
Write-Host "OVERALL=$overall"
