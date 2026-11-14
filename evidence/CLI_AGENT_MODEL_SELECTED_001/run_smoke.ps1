$ErrorActionPreference = 'Continue'
$ev = 'g:\~dev\rawrxd\evidence\CLI_AGENT_MODEL_SELECTED_001'
$run = "$ev\runs"
$ws = "$run\ws"
$exe = 'g:\~dev\rawrxd\build_ninja\bin\rawr.exe'
$model = 'G:\~dev\rawrxd\models\tinyllama.gguf'
$expect = '9797521CEB517B92AC52C518FB2BDB783628ABEA59366DFBE6E784C1A72951A3'
$outPath = "$run\run.out.txt"
$errPath = "$run\run.err.txt"
New-Item -ItemType Directory -Force -Path "$ws\scratch", $run | Out-Null
if (-not (Test-Path "$ws\README.md")) {
  Set-Content -Path "$ws\README.md" -Value "CLI_AGENT_MODEL_SELECTED_001 workspace`nUnforced agent smoke target.`n" -NoNewline
}
$sha = (Get-FileHash -Algorithm SHA256 $exe).Hash
$sha | Set-Content "$run\exe.sha256.txt"
if ($sha -ne $expect) {
  @"
DISPOSITION=SHA_MISMATCH
EXE_SHA256=$sha
EXPECT_SHA256=$expect
CROSS_SHA_CREDIT=0
PROMOTE=0
TIP_CLIMB=HOLD
GATE_STOP=1
"@ | Set-Content "$ev\STATUS.txt"
  Write-Output "SHA_MISMATCH"
  exit 2
}
Remove-Item Env:RAWR_AGENT_FORCE_TOOL -ErrorAction SilentlyContinue
Remove-Item Env:RAWR_AGENT_FORCE_PATH -ErrorAction SilentlyContinue
Remove-Item Env:RAWR_AGENT_FORCE_CONTENT -ErrorAction SilentlyContinue
function AbsOrAbsent([string]$v) {
  if ([string]::IsNullOrEmpty($v)) { return 'ABSENT' }
  return $v
}
@(
  "RAWR_AGENT_FORCE_TOOL=$(AbsOrAbsent $env:RAWR_AGENT_FORCE_TOOL)",
  "RAWR_AGENT_FORCE_PATH=$(AbsOrAbsent $env:RAWR_AGENT_FORCE_PATH)",
  "RAWR_AGENT_FORCE_CONTENT=$(AbsOrAbsent $env:RAWR_AGENT_FORCE_CONTENT)",
  "HOST_DECODE=0",
  "ALLOW_GPU=1"
) | Set-Content "$run\run.env.txt"

# Clear prior captures
Remove-Item $outPath, $errPath -ErrorAction SilentlyContinue
$env:HOST_DECODE = '0'
$env:ALLOW_GPU = '1'
$argList = @(
  'agent', $model,
  '--workspace', $ws,
  '--auto=full',
  '--max-tokens', '8',
  '-p', 'Read README.md then report'
)
$sw = [Diagnostics.Stopwatch]::StartNew()
$p = Start-Process -FilePath $exe -ArgumentList $argList `
  -WorkingDirectory 'g:\~dev\rawrxd' `
  -RedirectStandardOutput $outPath `
  -RedirectStandardError $errPath `
  -PassThru -NoNewWindow
$timeoutMs = 300000
$exited = $p.WaitForExit($timeoutMs)
$sw.Stop()
$killed = 0
if (-not $exited) {
  try { Stop-Process -Id $p.Id -Force } catch {}
  Start-Sleep -Seconds 3
  Get-Process rawr -ErrorAction SilentlyContinue | ForEach-Object {
    try { Stop-Process -Id $_.Id -Force } catch {}
  }
  $killed = 1
}
$exitCode = if ($exited) { $p.ExitCode } else { -1 }
"$exitCode" | Set-Content "$run\run.exit.txt"
$post = (Get-FileHash -Algorithm SHA256 $exe).Hash
$match = if ($sha -eq $expect) { '1' } else { '0' }
@"
ID=CLI_AGENT_MODEL_SELECTED_001
EXE=$exe
EXE_SHA256=$sha
EXE_SHA_POST=$post
SHA_MATCH=$match
EXPECT_SHA256=$expect
CROSS_SHA=0
CROSS_SHA_CREDIT=0
CMD=agent $model --workspace $ws --auto=full --max-tokens 8 -p "Read README.md then report"
RAWR_AGENT_FORCE_TOOL=ABSENT
HOST_DECODE=0
ALLOW_GPU=1
EXIT=$exitCode
KILLED=$killed
WALL_MS=$($sw.ElapsedMilliseconds)
ASOF=$((Get-Date).ToString('yyyy-MM-ddTHH:mm:ss.fffffffK'))
PROMOTE=0
TIP_CLIMB=HOLD
GATE_STOP=1
INVENT_PASS=0
"@ | Set-Content "$run\run.meta.txt"
Write-Output "EXIT=$exitCode KILLED=$killed WALL_MS=$($sw.ElapsedMilliseconds) SHA_MATCH=$match"
if (Test-Path $errPath) {
  Select-String -Path $errPath -Pattern 'MODEL_LOADED=|MODEL_SELECTED_TOOL=|FORCE_TOOL|parse FAILED|UNK_STREAK|chose tool=|DETERMINISTIC_TOOL|AGENT_LOOP|FILES_READ=|TOOL_EXECUTIONS=|GENERATED_TOKENS=|EARLY_VALID=|skip_model_load|AGENT_MODEL|CLEAN_EXIT|TD=' |
    ForEach-Object { $_.Line } | Select-Object -First 60
  Write-Output "ERR_BYTES=$((Get-Item $errPath).Length) OUT_BYTES=$((Get-Item $outPath -ErrorAction SilentlyContinue).Length)"
}
