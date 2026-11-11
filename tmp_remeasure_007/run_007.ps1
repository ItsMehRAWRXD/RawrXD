$ErrorActionPreference = 'Continue'
$outDir = 'F:\rawrxd\tmp_remeasure_007'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
Remove-Item Env:RAWRXD_ALLOW_GPU -ErrorAction SilentlyContinue
Remove-Item Env:RAWRXD_DEEP2_DEBUG -ErrorAction SilentlyContinue
Remove-Item Env:RAWRXD_DEEP2_NUMERIC_L2_LIMIT -ErrorAction SilentlyContinue
$env:RAWRXD_GREEDY = '1'

$exe = 'F:\rawrxd\build_tip_debug_rel\bin-msvc\rawr.exe'
$sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash
$stdout = Join-Path $outDir 'stdout.txt'
$stderr = Join-Path $outDir 'stderr.txt'
foreach ($f in @($stdout, $stderr)) { if (Test-Path $f) { Remove-Item -Force $f } }
$argList = @(
  'run', 'F:\rawrxd\gemma3-1b-Q2_K.gguf', 'ask',
  '--fresh-session',
  '--prompt', 'Say exactly: AGENT_RESULT=5',
  '--max-tokens', '32'
)
@("EXE_SHA=$sha","ARGS=$($argList -join ' ')","RAWRXD_GREEDY=1","FIX=ATTN_PRE_WO_preOCount","START=$((Get-Date).ToString('o'))") |
  Set-Content (Join-Path $outDir 'meta.txt')

$p = Start-Process -FilePath $exe -ArgumentList $argList `
  -WorkingDirectory 'F:\rawrxd\build_tip_debug_rel\bin-msvc' `
  -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
  -PassThru -NoNewWindow
"PID=$($p.Id)" | Add-Content (Join-Path $outDir 'meta.txt')
$sw = [Diagnostics.Stopwatch]::StartNew()
$exited = $p.WaitForExit(1800000)
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
$gen = ([regex]::Match($outText, 'POST_GENERATE generated=(\d+)')).Groups[1].Value
$greedy = ([regex]::Match(($outText + $errText), '\[GREEDY\] enabled=\d+[^\r\n]*')).Value
$headdim = ([regex]::Match($outText, 'HEADDIM_SYNC config[^\r\n]*')).Value
$postBind = ([regex]::Match($outText, 'HEADDIM_SYNC_POST_BIND[^\r\n]*')).Value
$abort = ([regex]::Match($errText, 'DEEP2_NUMERIC_ABORT[^\r\n]*')).Value
$prefillDone = ([regex]::Match($outText, 'PREFILL_DONE[^\r\n]*')).Value
$agent5 = [bool](($outText + $errText) -match 'AGENT_RESULT\s*=\s*5')
$pieces = ([regex]::Matches($outText, '\[AGENT\] TOKEN id=\d+ piece=([^\r\n]+)') | Select-Object -First 32 |
  ForEach-Object { $_.Groups[1].Value }) -join ''
$status = if ($agent5) { 'PASS' } else { 'PARTIAL' }
$gap = if ($status -eq 'PASS') { 'AGENT_RESULT=5' } else { "wall_s=$wall gen=$gen killed=$killed abort=$abort sample=$pieces" }
$receipt = @"
GATE=GEMMA_HEADDIM_RESCALE_REMEASURE_007
EXE=$exe
EXE_SHA=$sha
CMD=$($argList -join ' ')
RAWRXD_GREEDY=1
FIX=ATTN_PRE_WO validate wo.cols/attnConcat not hiddenDim tail
BOUND_TIMEOUT_S=1800
WALL_S=$wall
KILLED=$killed
EXIT=$exitCode
HEADDIM_SYNC=$headdim
HEADDIM_SYNC_POST_BIND=$postBind
GREEDY_LINE=$greedy
PREFILL_DONE=$prefillDone
ABORT=$abort
POST_GENERATE_GENERATED=$gen
SAMPLE_PIECES=$pieces
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
Write-Output 'REMEASURE_007_DONE'
