$ErrorActionPreference = 'Continue'
$outDir = 'F:\rawrxd\tmp_remeasure_010'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
Remove-Item Env:RAWRXD_ALLOW_GPU -ErrorAction SilentlyContinue
Remove-Item Env:RAWRXD_DEEP2_DEBUG -ErrorAction SilentlyContinue
$env:RAWRXD_GREEDY = '1'
$exe = 'F:\rawrxd\build_tip_debug_rel\bin-msvc\rawr.exe'
$shaLine = (certutil -hashfile $exe SHA256 | Select-Object -Skip 1 -First 1).Trim()
$stdout = Join-Path $outDir 'stdout.txt'
$stderr = Join-Path $outDir 'stderr.txt'
foreach ($f in @($stdout, $stderr)) { if (Test-Path $f) { Remove-Item -Force $f } }
$argLine = 'run F:\rawrxd\gemma3-1b-Q2_K.gguf ask --prompt "Say exactly: AGENT_RESULT=5" --max-tokens 32'
@("EXE_SHA=$shaLine","ARGS=$argLine","FIX=generateChat_configureGeneration_greedy","START=$((Get-Date).ToString('o'))") |
  Set-Content (Join-Path $outDir 'meta.txt')
$p = Start-Process -FilePath $exe -ArgumentList $argLine `
  -WorkingDirectory 'F:\rawrxd\build_tip_debug_rel\bin-msvc' `
  -RedirectStandardOutput $stdout -RedirectStandardError $stderr `
  -PassThru -NoNewWindow
"PID=$($p.Id)" | Add-Content (Join-Path $outDir 'meta.txt')
$sw = [Diagnostics.Stopwatch]::StartNew()
$exited = $p.WaitForExit(900000)
$killed = 0
if (-not $exited) { try { Stop-Process -Id $p.Id -Force } catch {}; $killed = 1; $exitCode = -1 }
else { $exitCode = $p.ExitCode }
$wall = [math]::Round($sw.Elapsed.TotalSeconds, 3)
$outText = if (Test-Path $stdout) { [IO.File]::ReadAllText($stdout) } else { '' }
$errText = if (Test-Path $stderr) { [IO.File]::ReadAllText($stderr) } else { '' }
# Fail-closed: NEVER match AGENT_RESULT=5 inside Formatted prompt dump
$askLine = ([regex]::Match($outText, '\[ask\] AGENT_RESULT_5=(\d+)[^\r\n]*')).Value
$askBit = ([regex]::Match($outText, '\[ask\] AGENT_RESULT_5=(\d+)')).Groups[1].Value
$idx = $outText.IndexOf('[ask] AGENT_RESULT_5=')
$sample = ''
if ($idx -gt 0) {
  $pre = $outText.Substring(0, $idx)
  $sample = if ($pre.Length -gt 240) { $pre.Substring($pre.Length - 240) } else { $pre }
}
$agent5 = ($askBit -eq '1')
$tmpl = ([regex]::Match($outText + $errText, 'Chat template: [^\r\n]+')).Value
$askPath = ([regex]::Match($errText, 'ASK_PATH=[^\r\n]+')).Value
$greedy = ([regex]::Match($outText + $errText, '\[GREEDY\] enabled=\d+[^\r\n]*')).Value
$prefill = ([regex]::Match($outText, 'PREFILL_DONE[^\r\n]*')).Value
$decode = ([regex]::Match($outText, 'DECODE_BEGIN[^\r\n]*')).Value
$fmtHead = ([regex]::Match($outText, 'Formatted prompt:\r?\n(<bos>[\s\S]{0,180})')).Groups[1].Value
$status = if ($agent5) { 'PASS' } else { 'PARTIAL' }
$receipt = @"
GATE=GEMMA_HEADDIM_RESCALE_REMEASURE_010
EXE_SHA=$shaLine
CMD=$argLine
ASK_PATH=$askPath
CHAT_TEMPLATE=$tmpl
GREEDY_LINE=$greedy
FORMATTED_PROMPT_HEAD=$fmtHead
PREFILL_DONE=$prefill
DECODE_BEGIN=$decode
ASK_LINE=$askLine
AGENT_RESULT_5=$agent5
WALL_S=$wall
KILLED=$killed
EXIT=$exitCode
STATUS=$status
GAP=$(if ($status -eq 'PASS') { 'AGENT_RESULT=5' } else { "askBit=$askBit sample=$sample" })
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
D015=HOLD
TIP_CLIMB=HOLD
"@
[IO.File]::WriteAllText((Join-Path $outDir 'receipt.txt'), $receipt)
Write-Output $receipt
Write-Output 'REMEASURE_010_DONE'
