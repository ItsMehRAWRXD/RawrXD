$ErrorActionPreference = 'Continue'
$base = "g:\~dev\rawrxd\evidence\PRODUCTION_MATURITY_TOP25_001\CLI_TOP25_VALUATION_001"
$wd = "g:\~dev\rawrxd"
$exePin = "g:\~dev\rawrxd\build_ninja\bin\rawr_v0_f28f10b9e510.exe"
$exe420 = "g:\~dev\rawrxd\build_ninja\bin\rawr.exe.broken_420ed"
$tag = "r29"

function Invoke-RawrSeal {
  param($RelPath, $Exe, $ArgLine, $EnvMap, $TimeoutMs)
  $out = Join-Path $base "$RelPath.out.txt"
  $err = Join-Path $base "$RelPath.err.txt"
  $exitf = Join-Path $base "$RelPath.exit.txt"
  $meta = Join-Path $base "$RelPath.meta.txt"
  $dir = Split-Path $out -Parent
  if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $Exe
  $psi.Arguments = $ArgLine
  $psi.WorkingDirectory = $wd
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.UseShellExecute = $false
  $psi.CreateNoWindow = $true
  foreach ($k in $EnvMap.Keys) { $psi.EnvironmentVariables[$k] = [string]$EnvMap[$k] }
  $sw = [Diagnostics.Stopwatch]::StartNew()
  $p = [Diagnostics.Process]::Start($psi)
  $oTask = $p.StandardOutput.ReadToEndAsync()
  $eTask = $p.StandardError.ReadToEndAsync()
  $ok = $p.WaitForExit($TimeoutMs)
  if (-not $ok) {
    try { $p.Kill() } catch {}
    $code = "TIMEOUT"
  } else {
    $code = "$($p.ExitCode)"
  }
  $sw.Stop()
  Start-Sleep -Milliseconds 300
  $o = $oTask.Result
  $e = $eTask.Result
  Set-Content -Path $out -Value $o -Encoding utf8
  Set-Content -Path $err -Value $e -Encoding utf8
  Set-Content -Path $exitf -Value "EXIT=$code" -Encoding utf8
  $sha = (Get-FileHash $Exe -Algorithm SHA256).Hash
  $hd = if ($e -match 'HOST_DECODE=(\d)') { $Matches[1] } else { "UNK" }
  $tok = if ($e -match '(?m)^GENERATED_TOKENS=(\d+)') { $Matches[1] } elseif ($e -match 'GENERATED_TOKENS=(\d+)') { $Matches[1] } else { "UNK" }
  $tps = if ($e -match 'DECODE_TPS_REAL=([0-9.]+)') { $Matches[1] } else { "UNK" }
  $be = if ($e -match 'decision=(\S+)') { $Matches[1] } else { "UNK" }
  $aok = if ($e -match 'AGENT_STATUS_OK=1' -or $o -match 'AGENT_STATUS_OK=1' -or $e -match 'AGENT_STATUS=1') { "1" } else { "0" }
  @(
    "EXE=$Exe"
    "EXE_SHA256=$sha"
    "CMD=$ArgLine"
    "ALLOW_GPU=1 HOST_DECODE_ENV=0 FORCE_GPU=1 NO_CPU_FALLBACK=1"
    "HOST_DECODE_OBS=$hd"
    "GENERATED_TOKENS=$tok"
    "DECODE_TPS_REAL=$tps"
    "BACKEND=$be"
    "AGENT_STATUS_OK=$aok"
    "EXIT=$code"
    "WALL_MS=$($sw.ElapsedMilliseconds)"
    "ASOF=$(Get-Date -Format o)"
    "PROMOTE=0"
    "TIP_CLIMB=HOLD"
  ) | Set-Content -Path $meta -Encoding utf8
  return "NAME=$RelPath EXIT=$code TOK=$tok TPS=$tps HD=$hd BE=$be AOK=$aok WALL=$($sw.ElapsedMilliseconds) SHA=$($sha.Substring(0,8))"
}

$gpuEnv = @{
  RAWRXD_ALLOW_GPU = '1'
  RAWR_FORCE_GPU = '1'
  RAWRXD_NO_CPU_FALLBACK = '1'
  RAWRXD_HOST_DECODE = '0'
  RAWRXD_CLI_GPU_LAW = '1'
  RAWRXD_WEIGHT_BUDGET = 'E8B0M'
}

Write-Output (Invoke-RawrSeal -RelPath "gpu\tiny_dense_$tag" -Exe $exePin -ArgLine "run models/tinyllama.gguf --vulkan -p Hello --max-tokens 16" -EnvMap $gpuEnv -TimeoutMs 180000)
Write-Output (Invoke-RawrSeal -RelPath "runs\agentic_chat_gpu_$tag" -Exe $exePin -ArgLine "chat models/tinyllama.gguf -p Hello --max-tokens 16" -EnvMap $gpuEnv -TimeoutMs 180000)
Write-Output (Invoke-RawrSeal -RelPath "runs\agent_status_$tag" -Exe $exe420 -ArgLine "agent status" -EnvMap @{} -TimeoutMs 15000)
Write-Output "SEAL_SCRIPT_DONE"
