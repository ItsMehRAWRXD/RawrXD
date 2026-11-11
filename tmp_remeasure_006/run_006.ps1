$ErrorActionPreference = 'Continue'
$outDir = 'F:\rawrxd\tmp_remeasure_006'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
Remove-Item Env:RAWRXD_ALLOW_GPU -ErrorAction SilentlyContinue
Remove-Item Env:RAWRXD_DEEP2_DEBUG -ErrorAction SilentlyContinue
$env:RAWRXD_GREEDY = '1'

$exe = 'F:\rawrxd\build_tip_debug_rel\bin-msvc\rawr.exe'
$sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash
$arg = 'run "F:\rawrxd\gemma3-1b-Q2_K.gguf" ask --fresh-session --prompt "Say exactly: AGENT_RESULT=5" --max-tokens 32'
$stdout = Join-Path $outDir 'stdout.txt'
$stderr = Join-Path $outDir 'stderr.txt'
@("EXE_SHA=$sha","ARGS=$arg","RAWRXD_GREEDY=1","START=$((Get-Date).ToString('o'))","BOUND_S=1200") |
  Set-Content (Join-Path $outDir 'meta.txt')

$p = Start-Process -FilePath $exe -ArgumentList $arg `
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
$greedy = ([regex]::Match(($outText + $errText), '\[GREEDY\][^\r\n]*')).Value
$headdim = ([regex]::Match($outText, 'HEADDIM_SYNC config[^\r\n]*')).Value
$agent5 = [bool](($outText + $errText) -match 'AGENT_RESULT\s*=\s*5')
# Collect first TOKEN pieces
$pieces = ([regex]::Matches($outText, '\[AGENT\] TOKEN id=\d+ piece=([^\r\n]+)') | Select-Object -First 16 |
  ForEach-Object { $_.Groups[1].Value }) -join ''
$status = if ($agent5) { 'PASS' } else { 'PARTIAL' }
$gap = if ($status -eq 'PASS') { 'AGENT_RESULT=5' } else { "wall_s=$wall gen=$gen killed=$killed sample=$pieces" }
$receipt = @"
GATE=GEMMA_HEADDIM_RESCALE_REMEASURE_006
EXE=$exe
EXE_SHA=$sha
CMD=$arg
RAWRXD_GREEDY=1
RAWRXD_ALLOW_GPU=UNSET
BOUND_TIMEOUT_S=1200
WALL_S=$wall
KILLED=$killed
EXIT=$exitCode
HEADDIM_SYNC=$headdim
GREEDY_LINE=$greedy
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
Write-Output 'REMEASURE_006_DONE'
