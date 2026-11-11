$ErrorActionPreference = 'Continue'
$outDir = 'F:\rawrxd\tmp_remeasure_008'
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
$argLine = 'run F:\rawrxd\gemma3-1b-Q2_K.gguf ask --fresh-session --prompt "Say exactly: AGENT_RESULT=5" --max-tokens 32'
@("EXE_SHA=$sha","ARGS=$argLine","RAWRXD_GREEDY=1","FIX=gemma_template+ask_max_tokens","START=$((Get-Date).ToString('o'))") |
  Set-Content (Join-Path $outDir 'meta.txt')

$p = Start-Process -FilePath $exe -ArgumentList $argLine `
  -WorkingDirectory 'F:\rawrxd\build_tip_debug_rel\bin-msvc' `
  -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
  -PassThru -NoNewWindow
"PID=$($p.Id)" | Add-Content (Join-Path $outDir 'meta.txt')
$sw = [Diagnostics.Stopwatch]::StartNew()
$exited = $p.WaitForExit(1200000)
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
$tmpl = ([regex]::Match($errText, 'Chat template: [^\r\n]+')).Value
$maxCfg = ([regex]::Match($errText, 'RUN_CONFIG_MAX_TOKENS=\d+')).Value
$abort = ([regex]::Match($errText, 'DEEP2_NUMERIC_ABORT[^\r\n]*')).Value
$prefillDone = ([regex]::Match($outText, 'PREFILL_DONE[^\r\n]*')).Value
$decode = ([regex]::Match($outText, 'DECODE_BEGIN[^\r\n]*')).Value
$agent5 = [bool](($outText + $errText) -match 'AGENT_RESULT\s*=\s*5')
$pieces = ([regex]::Matches($outText, '\[AGENT\] TOKEN id=\d+ piece=([^\r\n]+)') | Select-Object -First 32 |
  ForEach-Object { $_.Groups[1].Value }) -join ''
$status = if ($agent5) { 'PASS' } else { 'PARTIAL' }
$gap = if ($status -eq 'PASS') { 'AGENT_RESULT=5' } else { "wall_s=$wall gen=$gen killed=$killed tmpl=$tmpl max=$maxCfg decode=$decode abort=$abort sample=$pieces" }
$receipt = @"
GATE=GEMMA_HEADDIM_RESCALE_REMEASURE_008
EXE=$exe
EXE_SHA=$sha
CMD=$argLine
RAWRXD_GREEDY=1
FIX=gemma ChatTemplate + ASK_SYSTEM + --max-tokens honor + ask maxTurns=1
BOUND_TIMEOUT_S=1200
WALL_S=$wall
KILLED=$killed
EXIT=$exitCode
HEADDIM_SYNC=$headdim
GREEDY_LINE=$greedy
CHAT_TEMPLATE=$tmpl
RUN_CONFIG_MAX_TOKENS=$maxCfg
PREFILL_DONE=$prefillDone
DECODE_BEGIN=$decode
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
Write-Output 'REMEASURE_008_DONE'
