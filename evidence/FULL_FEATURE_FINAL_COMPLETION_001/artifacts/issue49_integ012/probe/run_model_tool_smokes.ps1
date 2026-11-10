# Fail-closed TOOL-protocol smokes. Host-seed OFF. Exclusive.
$ErrorActionPreference = "Continue"
$loop = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_012\deep2_agentic_loop.exe"
$workdir = "F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project"
$probeDir = "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ012\probe"
$matrix = Join-Path $probeDir "MODEL_TOOL_SMOKE_MATRIX.txt"
New-Item -ItemType Directory -Force -Path $probeDir | Out-Null
Remove-Item Env:RAWRXD_ISSUE49_HOST_SEED -ErrorAction SilentlyContinue
$env:RAWRXD_FORCE_LOCAL_AGENTIC = "1"
$env:RAWRXD_ISSUE49_HOST_SEED = "0"
$candidates = @(
  @{ Id="gemma3_latest"; Path="F:\rawrxd\models\gemma3_latest.gguf"; Wall=420; Prefill=32 },
  @{ Id="llama32_3b_Q3"; Path="F:\rawrxd\llama3.2-3b-Q3_K_S.gguf"; Wall=360; Prefill=32 },
  @{ Id="phi3_mini_Q2"; Path="F:\rawrxd\phi3-mini-Q2_K.gguf"; Wall=360; Prefill=32 },
  @{ Id="deepseek_v2_lite_chat"; Path="F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf"; Wall=480; Prefill=32 },
  @{ Id="nemotron3_nano_4b"; Path="F:\rawrxd\models\nemotron-3-nano_4b.gguf"; Wall=420; Prefill=32 },
  @{ Id="gemma3_1b_Q2"; Path="F:\rawrxd\gemma3-1b-Q2_K.gguf"; Wall=300; Prefill=32 }
)
function Kill-Loop { cmd.exe /c "taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1 & taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1" | Out-Null; Start-Sleep -Seconds 2 }
function Classify-Log([string]$logPath) {
  if (-not (Test-Path -LiteralPath $logPath)) { return "NO_LOG" }
  $t = Get-Content -LiteralPath $logPath -Raw -ErrorAction SilentlyContinue
  if ([string]::IsNullOrEmpty($t)) { return "EMPTY_LOG" }
  $toolPrefix = [int]($t -match "TOOL read_motd|TOOL write|RESULT_REINJECTION|TOOL read ")
  $toolCalls = [int]($t -match "MODEL_REQUESTED_TOOL\s+YES|tool_calls=([1-9])")
  $snapTool = [int]($t -match "expected TOOL protocol prefix")
  $eos = [int]($t -match "SNAP OUT RAW\] bytes=0|invalid_tool_format|generated 1 tokens / 0 chars")
  $kvFail = [int]($t -match "PARTIAL_KV|failing closed")
  $ingest = [regex]::Match($t, "ingest done[^\r\n]*").Value
  if ($toolPrefix -eq 1 -or $toolCalls -eq 1) { return "TOOL_PREFIX_EMITTED | $ingest" }
  if ($kvFail -eq 1) { return "LOAD_OR_PREFILL_FAIL_CLOSED | $ingest" }
  if ($eos -eq 1 -and $snapTool -eq 1) { return "EOS_EMPTY_SNAP_EXPECTED_TOOL | $ingest" }
  if ($snapTool -eq 1) { return "SNAP_STOP_EXPECTED_TOOL_PREFIX | $ingest" }
  if ($t -match "SNAP STOP") { return "SNAP_STOP_NO_TOOL | $ingest" }
  if ($t -match "loading model" -and $t -notmatch "ingest done") { return "LOAD_ABORT_OR_UNSTABLE" }
  return "UNKNOWN_NO_TOOL | $ingest"
}
$sb = New-Object System.Text.StringBuilder
[void]$sb.AppendLine("ASOF_UTC=$((Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"))")
[void]$sb.AppendLine("LOOP=$loop")
[void]$sb.AppendLine("HOST_SEED=OFF")
[void]$sb.AppendLine("OPAQUE_FIXTURE=$workdir")
[void]$sb.AppendLine("")
foreach ($c in $candidates) {
  $id=$c.Id; $path=$c.Path; $log=Join-Path $probeDir ("followup_{0}_tool_smoke.log" -f $id)
  Write-Host "=== PROBE $id ==="
  [void]$sb.AppendLine("CANDIDATE=$id"); [void]$sb.AppendLine("PATH=$path")
  if (-not (Test-Path -LiteralPath $path)) { [void]$sb.AppendLine("EXISTS=0"); [void]$sb.AppendLine("DISPOSITION=SKIP_MISSING_FILE"); [void]$sb.AppendLine(""); continue }
  $sizeMb=[math]::Round((Get-Item -LiteralPath $path).Length/1MB,1)
  [void]$sb.AppendLine("EXISTS=1 SIZE_MB=$sizeMb")
  Kill-Loop
  if (Test-Path -LiteralPath $log) { Remove-Item -LiteralPath $log -Force }
  $argList = "--model `"$path`" --workdir `"$workdir`" --target-file bug.cpp --task `"Fix bug.cpp so undeclared_fn(1,2) compiles. Reply TOOL read_motd first.`" --max-steps 3 --max-new 64 --max-wall-time-sec $($c.Wall) --prefill-chunk $($c.Prefill)"
  $p = Start-Process -FilePath $loop -ArgumentList $argList -WorkingDirectory $workdir -RedirectStandardOutput $log -RedirectStandardError "$log.err" -PassThru -NoNewWindow
  $deadline=(Get-Date).AddSeconds([int]$c.Wall + 90)
  while (-not $p.HasExited -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 5 }
  if (-not $p.HasExited) { try{$p.Kill()}catch{}; Kill-Loop; [void]$sb.AppendLine("TIMEOUT_KILL=1") } else { [void]$sb.AppendLine("EXIT=$($p.ExitCode)") }
  Start-Sleep -Seconds 1
  if ((Test-Path "$log.err") -and (Get-Item "$log.err").Length -gt 0) { Add-Content -LiteralPath $log -Value (Get-Content "$log.err" -Raw) }
  $cls = Classify-Log $log
  [void]$sb.AppendLine("LOG=$log"); [void]$sb.AppendLine("DISPOSITION=$cls")
  Select-String -LiteralPath $log -Pattern "SNAP protocol|expected TOOL|SNAP OUT|SNAP STOP|RESULT_REINJECTION|TOOL read|model_output|invalid_tool|failing closed|PARTIAL|ingest done|generated .* tokens|MODEL_REQUESTED_TOOL|FINAL_VERDICT" -ErrorAction SilentlyContinue | Select-Object -First 15 | ForEach-Object { [void]$sb.AppendLine("HIT=$($_.Line.Trim())") }
  [void]$sb.AppendLine("")
  Set-Content -LiteralPath $matrix -Value $sb.ToString() -Encoding ASCII
  Write-Host "DONE $id => $cls"
}
Kill-Loop
[void]$sb.AppendLine("MATRIX_COMPLETE=1")
Set-Content -LiteralPath $matrix -Value $sb.ToString() -Encoding ASCII
Write-Host "MATRIX_WRITTEN=$matrix"
