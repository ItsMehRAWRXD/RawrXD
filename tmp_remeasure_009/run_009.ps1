$ErrorActionPreference = 'Continue'
$outDir = 'F:\rawrxd\tmp_remeasure_009'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
Remove-Item Env:RAWRXD_ALLOW_GPU -ErrorAction SilentlyContinue
Remove-Item Env:RAWRXD_DEEP2_DEBUG -ErrorAction SilentlyContinue
$env:RAWRXD_GREEDY = '1'
$exe = 'F:\rawrxd\build_tip_debug_rel\bin-msvc\rawr.exe'
$sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash
$stdout = Join-Path $outDir 'stdout.txt'
$stderr = Join-Path $outDir 'stderr.txt'
foreach ($f in @($stdout, $stderr)) { if (Test-Path $f) { Remove-Item -Force $f } }
$argLine = 'run F:\rawrxd\gemma3-1b-Q2_K.gguf ask --prompt "Say exactly: AGENT_RESULT=5" --max-tokens 32'
@("EXE_SHA=$sha","ARGS=$argLine","FIX=generateChat+bos+single_user","START=$((Get-Date).ToString('o'))") |
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
$gen = ([regex]::Match($outText, 'POST_GENERATE generated=(\d+)')).Groups[1].Value
$tmpl = ([regex]::Match($outText + $errText, 'Chat template: [^\r\n]+')).Value
$askPath = ([regex]::Match($errText, 'ASK_PATH=[^\r\n]+')).Value
$fmt = ([regex]::Match($outText, 'Formatted prompt:\r?\n([\s\S]{0,500})')).Groups[1].Value
$agent5 = [bool](($outText + $errText) -match 'AGENT_RESULT\s*=\s*5')
$askLine = ([regex]::Match($outText, '\[ask\] AGENT_RESULT_5=\d+[^\r\n]*')).Value
$decode = ([regex]::Match($outText, 'DECODE_BEGIN[^\r\n]*')).Value
$prefill = ([regex]::Match($outText, 'PREFILL_DONE[^\r\n]*')).Value
$sample = ($outText -replace '(?s).*?(?=\[ask\]|Summary:|$)', '')
if ($sample.Length -gt 200) { $sample = $sample.Substring(0, 200) }
$status = if ($agent5) { 'PASS' } else { 'PARTIAL' }
$receipt = @"
GATE=GEMMA_HEADDIM_RESCALE_REMEASURE_009
EXE_SHA=$sha
CMD=$argLine
ASK_PATH=$askPath
CHAT_TEMPLATE=$tmpl
FORMATTED_PROMPT_HEAD=$fmt
PREFILL_DONE=$prefill
DECODE_BEGIN=$decode
POST_GENERATE_GENERATED=$gen
ASK_LINE=$askLine
AGENT_RESULT_5=$agent5
WALL_S=$wall
KILLED=$killed
EXIT=$exitCode
STATUS=$status
GAP=$(if ($status -eq 'PASS') { 'AGENT_RESULT=5' } else { "sample=$sample" })
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
D015=HOLD
TIP_CLIMB=HOLD
"@
[IO.File]::WriteAllText((Join-Path $outDir 'receipt.txt'), $receipt)
Write-Output $receipt
Write-Output 'REMEASURE_009_DONE'
