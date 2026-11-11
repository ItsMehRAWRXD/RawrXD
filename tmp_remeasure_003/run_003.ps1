$ErrorActionPreference = 'Continue'
$outDir = 'F:\rawrxd\tmp_remeasure_003'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
Set-Location 'F:\rawrxd\build_tip_debug_rel'

Remove-Item Env:RAWRXD_ALLOW_GPU -ErrorAction SilentlyContinue
Remove-Item Env:RAWRXD_DEEP2_DEBUG -ErrorAction SilentlyContinue
[Environment]::SetEnvironmentVariable('RAWRXD_ALLOW_GPU', $null, 'Process')
[Environment]::SetEnvironmentVariable('RAWRXD_DEEP2_DEBUG', $null, 'Process')

"BUILD_START=$((Get-Date).ToString('o'))" | Set-Content (Join-Path $outDir 'build.txt')
$vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat'
$buildCmd = "`"$vcvars`" && cmake --build F:\rawrxd\build_tip_debug_rel --target RawrXD-CLI-V2 -j 8"
cmd /c $buildCmd 2>&1 |
  Tee-Object -FilePath (Join-Path $outDir 'build_log.txt')
"BUILD_END=$((Get-Date).ToString('o')) EXIT=$LASTEXITCODE" | Add-Content (Join-Path $outDir 'build.txt')
if ($LASTEXITCODE -ne 0) {
  'BUILD_FAIL' | Set-Content (Join-Path $outDir 'status.txt')
  exit $LASTEXITCODE
}

$exe = 'F:\rawrxd\build_tip_debug_rel\bin-msvc\rawr.exe'
$sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash
"EXE_SHA=$sha" | Set-Content (Join-Path $outDir 'meta.txt')
"PRIOR_REF=4179D83105152C52C2F98D4490D704D19A3BDD180735FC32CE891BF76468902E" | Add-Content (Join-Path $outDir 'meta.txt')
"DIFFERS=$(if ($sha -ne '4179D83105152C52C2F98D4490D704D19A3BDD180735FC32CE891BF76468902E') {'1'} else {'0'})" | Add-Content (Join-Path $outDir 'meta.txt')

$stdout = Join-Path $outDir 'stdout.txt'
$stderr = Join-Path $outDir 'stderr.txt'
$arg = 'run "F:\rawrxd\gemma3-1b-Q2_K.gguf" ask --prompt "Say exactly: AGENT_RESULT=5" --max-tokens 16'
"ARGS=$arg" | Add-Content (Join-Path $outDir 'meta.txt')
"START=$((Get-Date).ToString('o'))" | Add-Content (Join-Path $outDir 'meta.txt')

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
} else {
  $exitCode = $p.ExitCode
}
$wall = [math]::Round($sw.Elapsed.TotalSeconds, 3)
$outText = if (Test-Path $stdout) { [IO.File]::ReadAllText($stdout) } else { '' }
$errText = if (Test-Path $stderr) { [IO.File]::ReadAllText($stderr) } else { '' }
$l12n = ([regex]::Matches($errText, 'L12_DIAG')).Count
$kvn = ([regex]::Matches($errText, 'KV_DIAG')).Count
$tok = 0
$tm = [regex]::Matches(($outText + "`n" + $errText), 'TOKENS_DECODED=(\d+)')
if ($tm.Count -gt 0) { $tok = [int]$tm[$tm.Count - 1].Groups[1].Value }
$agent5 = [bool](($outText + $errText) -match 'AGENT_RESULT\s*=\s*5')
$headdim = ([regex]::Match($outText + $errText, 'HEADDIM_SYNC[^\r\n]*')).Value
$rescale = ([regex]::Match($errText, 'DEEP2_NUMERIC_RESCALE[^\r\n]*')).Value
$abortN = ([regex]::Matches(($outText + $errText), 'DEEP2_NUMERIC_ABORT')).Count
$status = 'PARTIAL'
if ($agent5 -or ($tok -gt 0)) { $status = 'PASS' }
$gap = if ($status -eq 'PASS') { 'emission_proven' } else { "wall_s=$wall tok=$tok killed=$killed l12=$l12n kv=$kvn" }

@(
  "END=$((Get-Date).ToString('o'))"
  "WALL_S=$wall"
  "KILLED=$killed"
  "EXIT=$exitCode"
  "TOKENS_DECODED=$tok"
  "AGENT_RESULT_5=$agent5"
  "L12_DIAG_COUNT=$l12n"
  "KV_DIAG_COUNT=$kvn"
  "STATUS=$status"
) | Add-Content (Join-Path $outDir 'meta.txt')

$receipt = @"
GATE=GEMMA_HEADDIM_RESCALE_REMEASURE_003
EXE=$exe
EXE_SHA=$sha
PRIOR_SHA_REF=4179D83105152C52C2F98D4490D704D19A3BDD180735FC32CE891BF76468902E
EXE_SHA_DIFFERS_FROM_PRIOR=$(if ($sha -ne '4179D83105152C52C2F98D4490D704D19A3BDD180735FC32CE891BF76468902E') {'1'} else {'0'})
MODEL=F:\rawrxd\gemma3-1b-Q2_K.gguf
CMD=$arg
RAWRXD_ALLOW_GPU=UNSET
RAWRXD_DEEP2_DEBUG=UNSET
BOUND_TIMEOUT_S=600
WALL_S=$wall
KILLED=$killed
EXIT=$exitCode
HEADDIM_SYNC=$headdim
RESCALE=$rescale
ABORT_COUNT=$abortN
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
Write-Output 'REMEASURE_003_DONE'
