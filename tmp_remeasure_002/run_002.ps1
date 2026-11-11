$ErrorActionPreference = 'Continue'
$outDir = 'F:\rawrxd\tmp_remeasure_002'
$evDir  = 'g:\~dev\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\FINALIZATION_CHECKLIST_001'
New-Item -ItemType Directory -Force -Path $outDir | Out-Null
$stdout = Join-Path $outDir 'stdout.txt'
$stderr = Join-Path $outDir 'stderr.txt'
$meta   = Join-Path $outDir 'meta.txt'
$receipt = Join-Path $outDir 'receipt.txt'
Remove-Item Env:RAWRXD_ALLOW_GPU -ErrorAction SilentlyContinue
[Environment]::SetEnvironmentVariable('RAWRXD_ALLOW_GPU', $null, 'Process')

$existing = @(Get-Process -Name rawr -ErrorAction SilentlyContinue)
if ($existing.Count -gt 0) {
  "EXISTING_RAWR=" + (($existing | ForEach-Object { $_.Id }) -join ',') | Set-Content (Join-Path $outDir 'existing.txt')
}

$exe = 'F:\rawrxd\build_tip_debug_rel\bin-msvc\rawr.exe'
$sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $exe).Hash
$args = 'run "F:\rawrxd\gemma3-1b-Q2_K.gguf" ask --prompt "Say exactly: AGENT_RESULT=5" --max-tokens 16'
"EXE_SHA=$sha" | Set-Content $meta
"ARGS=$args" | Add-Content $meta
"START=$((Get-Date).ToString('o'))" | Add-Content $meta

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $exe
$psi.WorkingDirectory = 'F:\rawrxd\build_tip_debug_rel\bin-msvc'
$psi.Arguments = $args
$psi.UseShellExecute = $false
$psi.RedirectStandardOutput = $true
$psi.RedirectStandardError = $true
$psi.CreateNoWindow = $true
$p = New-Object System.Diagnostics.Process
$p.StartInfo = $psi
$outSb = New-Object System.Text.StringBuilder
$errSb = New-Object System.Text.StringBuilder
$p.add_OutputDataReceived({ param($s,$e) if ($null -ne $e.Data) { [void]$outSb.AppendLine($e.Data) } })
$p.add_ErrorDataReceived({ param($s,$e) if ($null -ne $e.Data) { [void]$errSb.AppendLine($e.Data) } })
$sw = [Diagnostics.Stopwatch]::StartNew()
[void]$p.Start()
$p.BeginOutputReadLine()
$p.BeginErrorReadLine()
"PID=$($p.Id)" | Add-Content $meta
$exited = $p.WaitForExit(900000)
$killed = 0
if (-not $exited) {
  try { $p.Kill() } catch {}
  Start-Sleep 2
  try { [void]$p.WaitForExit(15000) } catch {}
  $killed = 1
  $exitCode = -1
} else {
  $exitCode = $p.ExitCode
}
Start-Sleep -Milliseconds 800
$outText = $outSb.ToString()
$errText = $errSb.ToString()
[IO.File]::WriteAllText($stdout, $outText)
[IO.File]::WriteAllText($stderr, $errText)
$wall = [math]::Round($sw.Elapsed.TotalSeconds, 3)
$lastWp = ''
$m = [regex]::Matches($errText, 'writePos=(\d+)')
if ($m.Count -gt 0) { $lastWp = $m[$m.Count-1].Groups[1].Value }
$tokDec = 0
$tm = [regex]::Matches(($outText + "`n" + $errText), 'TOKENS_DECODED=(\d+)')
if ($tm.Count -gt 0) { $tokDec = [int]$tm[$tm.Count-1].Groups[1].Value }
$agent5 = [bool](($outText + $errText) -match 'AGENT_RESULT\s*=\s*5')
$headdim = ([regex]::Match($outText + $errText, 'HEADDIM_SYNC[^\r\n]*')).Value
$rescale = ([regex]::Match($errText, 'DEEP2_NUMERIC_RESCALE[^\r\n]*')).Value
$abortN = ([regex]::Matches(($outText + $errText), 'DEEP2_NUMERIC_ABORT')).Count
$status = 'PARTIAL'
if ($agent5 -or ($tokDec -gt 0 -and ($outText.Length -gt 200))) { $status = 'PASS' }
$gap = if ($status -eq 'PASS') { 'emission_proven' } else { "wall_s=$wall last_writePos=$lastWp tok=$tokDec killed=$killed" }

@(
  "END=$((Get-Date).ToString('o'))"
  "WALL_S=$wall"
  "KILLED=$killed"
  "EXIT=$exitCode"
  "LAST_WRITEPOS=$lastWp"
  "TOKENS_DECODED=$tokDec"
  "AGENT_RESULT_5=$agent5"
  "STDOUT_BYTES=$($outText.Length)"
  "STDERR_BYTES=$($errText.Length)"
  "STATUS=$status"
) | Add-Content $meta

$receiptBody = @"
GATE=GEMMA_HEADDIM_RESCALE_REMEASURE_002
EXE=F:\rawrxd\build_tip_debug_rel\bin-msvc\rawr.exe
EXE_SHA=$sha
MODEL=F:\rawrxd\gemma3-1b-Q2_K.gguf
CMD=$args
RAWRXD_ALLOW_GPU=UNSET
BOUND_TIMEOUT_S=900
WALL_S=$wall
KILLED=$killed
EXIT=$exitCode
HEADDIM_SYNC=$headdim
RESCALE=$rescale
ABORT_COUNT=$abortN
LAST_WRITEPOS=$lastWp
TOKENS_DECODED=$tokDec
AGENT_RESULT_5=$agent5
STATUS=$status
GAP=$gap
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
D015=HOLD
TIP_CLIMB=HOLD
"@
[IO.File]::WriteAllText($receipt, $receiptBody)
Copy-Item -Force $stdout (Join-Path $evDir 'GEMMA_HEADDIM_RESCALE_REMEASURE_002.stdout.txt') -ErrorAction SilentlyContinue
Copy-Item -Force $stderr (Join-Path $evDir 'GEMMA_HEADDIM_RESCALE_REMEASURE_002.stderr.txt') -ErrorAction SilentlyContinue
Copy-Item -Force $meta   (Join-Path $evDir 'GEMMA_HEADDIM_RESCALE_REMEASURE_002.meta.txt') -ErrorAction SilentlyContinue
Copy-Item -Force $receipt (Join-Path $evDir 'GEMMA_HEADDIM_RESCALE_REMEASURE_002.txt') -ErrorAction SilentlyContinue
Write-Output $receiptBody
Write-Output 'REMEASURE_002_DONE'
