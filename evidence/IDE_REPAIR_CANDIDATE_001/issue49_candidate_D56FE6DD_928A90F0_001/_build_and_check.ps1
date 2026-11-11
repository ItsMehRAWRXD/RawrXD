$ErrorActionPreference = 'Stop'
$log = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_candidate_D56FE6DD_928A90F0_001\_build_log.txt'
function L($m) { Add-Content -LiteralPath $log -Value $m; Write-Output $m }
'' | Set-Content -LiteralPath $log

# Prefer build tree whose current exe matches frozen LOOP sha (qt_free).
$build = 'F:\rawrxd\build_qt_free'
$vs = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
if (-not (Test-Path $vs)) {
  $vs = 'C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat'
}
if (-not (Test-Path $vs)) { throw 'vcvars64.bat missing' }

# Reconfigure so /utf-8 lands, then build only deep2_agentic_loop.
$cmd = @"
call `"$vs`"
cd /d `"$build`"
cmake `"F:\rawrxd`" 1>>`"$log`" 2>>&1
cmake --build . --target deep2_agentic_loop --config Release -j 2 1>>`"$log`" 2>>&1
echo BUILD_EXIT=!ERRORLEVEL!
"@
$bat = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_candidate_D56FE6DD_928A90F0_001\_build_tmp.bat'
Set-Content -LiteralPath $bat -Value $cmd -Encoding ASCII
cmd /c $bat
$exitLine = Get-Content $log | Select-String 'BUILD_EXIT=' | Select-Object -Last 1
L "$exitLine"

$built = @(
  (Join-Path $build 'bin\Release\deep2_agentic_loop.exe'),
  (Join-Path $build 'bin\deep2_agentic_loop.exe'),
  (Join-Path $build 'Release\deep2_agentic_loop.exe')
) | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $built) { throw 'built exe not found' }
L "BUILT=$built"
$sha = (Get-FileHash -LiteralPath $built -Algorithm SHA256).Hash.ToUpperInvariant()
L "NEW_LOOP_SHA256=$sha"

# Verify no 0x97 before ' either use'
$eb = [IO.File]::ReadAllBytes($built)
$needle = [Text.Encoding]::ASCII.GetBytes('C4100 unused parameter under /WX ')
$found = -1
for ($i = 0; $i -lt $eb.Length - $needle.Length - 20; $i++) {
  $ok = $true
  for ($j = 0; $j -lt $needle.Length; $j++) { if ($eb[$i+$j] -ne $needle[$j]) { $ok=$false; break } }
  if ($ok) { $found = $i; break }
}
L "C4100_HINT_OFS=$found"
if ($found -ge 0) {
  $after = $eb[($found + $needle.Length)]
  L ('BYTE_AFTER_WX_SPACE=0x{0:X2}' -f $after)
  $slice = -join ($eb[($found)..($found+80)] | ForEach-Object { if ($_ -ge 32 -and $_ -le 126) { [char]$_ } else { '.' } })
  L "HINT_ASCII=$slice"
}

$dest = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_candidate_D56FE6DD_928A90F0_001\bin\deep2_agentic_loop.exe'
Copy-Item -LiteralPath $built -Destination $dest -Force
$destSha = (Get-FileHash -LiteralPath $dest -Algorithm SHA256).Hash.ToUpperInvariant()
L "COPIED_DEST_SHA256=$destSha"
L 'BUILD_CHECK_OK'