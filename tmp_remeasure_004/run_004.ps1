$ErrorActionPreference = 'Continue'
$outDir = 'F:\rawrxd\tmp_remeasure_004'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$alive = @(Get-Process -Name rawr -ErrorAction SilentlyContinue)
if ($alive.Count -gt 0) {
  "WAIT_FOR_RAWR_EXIT pids=$($alive.Id -join ',')" | Set-Content (Join-Path $outDir 'wait.txt')
  $deadline = (Get-Date).AddSeconds(700)
  while ((Get-Date) -lt $deadline) {
    if (-not (Get-Process -Name rawr -ErrorAction SilentlyContinue)) { break }
    Start-Sleep -Seconds 5
  }
  if (Get-Process -Name rawr -ErrorAction SilentlyContinue) {
    'STILL_BUSY_ABORT' | Set-Content (Join-Path $outDir 'status.txt')
    exit 2
  }
}

Remove-Item Env:RAWRXD_ALLOW_GPU -ErrorAction SilentlyContinue
Remove-Item Env:RAWRXD_DEEP2_DEBUG -ErrorAction SilentlyContinue
$vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
"BUILD_START=$((Get-Date).ToString('o'))" | Set-Content (Join-Path $outDir 'build.txt')
# ninja has no phony "rawr"; OUTPUT_NAME rawr.exe comes from RawrXD-CLI-V2
cmd /c "`"$vcvars`" && cmake --build F:\rawrxd\build_tip_debug_rel --target RawrXD-CLI-V2 -j 8" 2>&1 |
  Tee-Object -FilePath (Join-Path $outDir 'build_log.txt')
"BUILD_END=$((Get-Date).ToString('o')) EXIT=$LASTEXITCODE" | Add-Content (Join-Path $outDir 'build.txt')
if ($LASTEXITCODE -ne 0) { 'BUILD_FAIL' | Set-Content (Join-Path $outDir 'status.txt'); exit $LASTEXITCODE }

$exe = 'F:\rawrxd\build_tip_debug_rel\bin-msvc\rawr.exe'
$sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash
$arg = 'run "F:\rawrxd\gemma3-1b-Q2_K.gguf" ask --prompt "Say exactly: AGENT_RESULT=5" --max-tokens 16'
$stdout = Join-Path $outDir 'stdout.txt'
$stderr = Join-Path $outDir 'stderr.txt'
@("EXE_SHA=$sha","ARGS=$arg","START=$((Get-Date).ToString('o'))") | Set-Content (Join-Path $outDir 'meta.txt')

$p = Start-Process -FilePath $exe -ArgumentList $arg `
  -WorkingDirectory 'F:\rawrxd\build_tip_debug_rel\bin-msvc' `
  -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
  -PassThru -NoNewWindow
"PID=$($p.Id)" | Add-Content (Join-Path $outDir 'meta.txt')
$sw = [Diagnostics.Stopwatch]::StartNew()
$exited = $p.WaitForExit(600000)
$killed = 0
if (-not $exited) {
  try { Stop-Process -Id $p.Id -Force } catch {}
  Start-Sleep 2
  $killed = 1
  $exitCode = -1
} else { $exitCode = $p.ExitCode }
$wall = [math]::Round($sw.Elapsed.TotalSeconds, 3)
$outText = if (Test-Path $stdout) { [IO.File]::ReadAllText($stdout) } else { '' }
$errText = if (Test-Path $stderr) { [IO.File]::ReadAllText($stderr) } else { '' }
$tok = 0
$tm = [regex]::Matches(($outText + "`n" + $errText), 'TOKENS_DECODED=(\d+)')
if ($tm.Count -gt 0) { $tok = [int]$tm[$tm.Count-1].Groups[1].Value }
$agent5 = [bool](($outText + $errText) -match 'AGENT_RESULT\s*=\s*5')
$headdim = ([regex]::Match($outText, 'HEADDIM_SYNC[^\r\n]*')).Value
$post = ([regex]::Match($outText, 'HEADDIM_SYNC_POST_BIND[^\r\n]*')).Value
$override = ([regex]::Match($outText, 'headDim override[^\r\n]*')).Value
$rescale = ([regex]::Match($errText, 'DEEP2_NUMERIC_RESCALE[^\r\n]*')).Value
$abortN = ([regex]::Matches(($outText + $errText), 'DEEP2_NUMERIC_ABORT')).Count
$topoN = ([regex]::Matches($errText, 'ATTN_TOPOLOGY')).Count
$l12n = ([regex]::Matches($errText, 'L12_DIAG')).Count
$kvn = ([regex]::Matches($errText, 'KV_DIAG')).Count
$kvAlloc = ([regex]::Match($outText, 'KV cache: [^\r\n]*')).Value
$status = if ($agent5 -or ($tok -gt 0)) { 'PASS' } else { 'PARTIAL' }
$gap = if ($status -eq 'PASS') { 'emission_proven' } else { "wall_s=$wall tok=$tok killed=$killed topo=$topoN" }
$receipt = @"
GATE=GEMMA_HEADDIM_RESCALE_REMEASURE_004
EXE=$exe
EXE_SHA=$sha
CMD=$arg
RAWRXD_ALLOW_GPU=UNSET
RAWRXD_DEEP2_DEBUG=UNSET
BOUND_TIMEOUT_S=600
WALL_S=$wall
KILLED=$killed
EXIT=$exitCode
HEADDIM_OVERRIDE=$override
HEADDIM_SYNC=$headdim
HEADDIM_SYNC_POST_BIND=$post
KV_ALLOC=$kvAlloc
RESCALE=$rescale
ABORT_COUNT=$abortN
ATTN_TOPOLOGY_COUNT=$topoN
L12_DIAG_COUNT=$l12n
KV_DIAG_COUNT=$kvn
TOKENS_DECODED=$tok
AGENT_RESULT_5=$agent5
STATUS=$status
GAP=$gap
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
D015=HOLD
TIP_CLIMB=HOLD
"@
[IO.File]::WriteAllText((Join-Path $outDir 'receipt.txt'), $receipt)
Write-Output $receipt
Write-Output 'REMEASURE_004_DONE'
