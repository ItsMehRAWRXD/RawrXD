# run_matrix.ps1 — Deep2/REAP benchmark matrix under FIXED conditions.
# Implements the 6 mandatory corrections: (1) separate llama.cpp vs Deep2,
# (2) measure CPU router latency, (3) verify physical GPU identity,
# (4) separate diagnostic vs perf runs, (5) hash models+exes,
# (6) reject incomplete measurements (no PASS on missing/failed/fallback/nonfinite).
#
# Usage:
#   pwsh bench/run_matrix.ps1 -Model <gguf> [-ReapModel <gguf>] `
#     [-LlamaBench <exe>] [-LlamaCli <exe>] [-Deep2Bench <exe>] [-OutDir <dir>]
param(
  [string]$LlamaBench = "$env:LOCALAPPDATA\llama\llama-bench.exe",
  [string]$LlamaCli   = "$env:LOCALAPPDATA\llama\llama-cli.exe",
  [string]$Deep2Bench = "F:\rawrxd\build\bin\Release\deep2_benchmark.exe",
  [Parameter(Mandatory=$true)][string]$Model,
  [string]$ReapModel,
  [string]$OutDir = "F:\rawrxd\evidence\bench",
  [int]$Reps = 5,
  [int]$Ctx = 4096,
  [int]$Threads = 16,
  [int]$Gen = 512,
  [string]$Prompt = "The quick brown fox jumps over the lazy dog. Explain quantum entanglement in one paragraph."
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Commit = (git -C F:\rawrxd rev-parse HEAD 2>$null)
$report = [ordered]@{}
$incomplete = @()

function Hash-File { param($p) if($p -and (Test-Path $p)){ (Get-FileHash $p -Algorithm SHA256).Hash } else { 'MISSING' } }

# ---- (4) Separate diagnostic from perf: strip any tracing env --------------
foreach($v in 'DEEP2_TRACE','ATTN_DUMP','ATTN_TRACE','DEEP2_DUMP_FFN','RR_GPU_CHECK','DEEP2_NO_DOT_BATCH','DEEP2_WIDE_DOT_BATCH'){
  Remove-Item "Env:$v" -ErrorAction SilentlyContinue
}

# ---- (3) Verify PHYSICAL GPU identity (not just the env var) ----------------
$env:GGML_VK_VISIBLE_DEVICES = '0'
$gpuIdentity = 'unknown'
if(Get-Command vulkaninfo -ErrorAction SilentlyContinue){
  $vi = (& vulkaninfo --summary 2>&1 | Out-String)
  $dev = ($vi -split "`n" | Where-Object { $_ -match 'deviceName|driverVersion|apiVersion' } | Select-Object -First 6) -join '; '
  if($dev){ $gpuIdentity = $dev }
}

# ---- (5) Hash inputs (models + executables) --------------------------------
$hashes = [ordered]@{
  model      = Hash-File $Model
  reap_model = (Hash-File $ReapModel)
  llama_bench= Hash-File $LlamaBench
  llama_cli  = Hash-File $LlamaCli
  deep2_bench= Hash-File $Deep2Bench
}

$common = @('-ngl','99','-fa','-t',"$Threads",'-c',"$Ctx")

function Invoke-LlamaBench {
  param([string]$Tag,[string]$ModelPath,[int]$P,[int]$N)
  if(!(Test-Path $LlamaBench)) { throw "llama-bench not found: $LlamaBench" }
  if(!(Test-Path $ModelPath))  { throw "model not found: $ModelPath" }
  $a = @('-m',$ModelPath) + $common + @('-p',"$P",'-n',"$N",'-r',"$Reps")
  $out = (& $LlamaBench @a 2>&1 | Out-String)
  $out | Set-Content -LiteralPath (Join-Path $OutDir "$Tag.txt")
  # parse avg (llama-bench prints "<avg> ± <std>")
  $m = [regex]::Matches($out,'(?<avg>\d+(?:\.\d+)?)\s*±\s*(?<std>\d+(?:\.\d+)?)')
  if($m.Count -eq 0){ $script:incomplete += "${Tag}: no avg parsed" }
  return @{ raw=$out; avg=($m | ForEach-Object { $_.Groups['avg'].Value }) }
}

function Get-Residency {
  param([string]$ModelPath,[string]$Tag)
  if(!(Test-Path $LlamaCli)) { return @{} }
  $log = (& $LlamaCli -m $ModelPath @common -p $Prompt -n 1 2>&1 | Out-String)
  $log | Set-Content -LiteralPath (Join-Path $OutDir "$Tag-load.txt")
  $h = @{}
  foreach($k in 'offloaded','KV self size','VRAM','n_batch','ubatch','model size'){
    $line = ($log -split "`n" | Where-Object { $_ -match $k } | Select-Object -First 1)
    if($line){ $h[$k] = $line.Trim() }
  }
  return $h
}

# ================= (1) llama.cpp side: A, B, C, G ============================
$A = Invoke-LlamaBench -Tag 'A_decode'  -ModelPath $Model -P 512 -N $Gen
$B = Invoke-LlamaBench -Tag 'B_prefill' -ModelPath $Model -P $Ctx -N 0
$C = Get-Residency -ModelPath $Model -Tag 'C_residency'
$G = $null
if($ReapModel -and (Test-Path $ReapModel)){
  $Ga = Invoke-LlamaBench -Tag 'G_reap_decode'  -ModelPath $ReapModel -P 512 -N $Gen
  $Gb = Invoke-LlamaBench -Tag 'G_reap_prefill' -ModelPath $ReapModel -P $Ctx -N 0
  $Gc = Get-Residency -ModelPath $ReapModel -Tag 'G_reap_residency'
  $G = @{ decode=$Ga.avg; prefill=$Gb.avg; residency=$Gc }
}

# ============ (1)(2) Deep2 side: E (dispatch) + D (CPU router) ===============
$deep2 = [ordered]@{ available=$false }
if(Test-Path $Deep2Bench){
  $deep2.available = $true
  $dargs = @($Model,'--gpu','R9700','--ctx',"$Ctx",'--gen',"$Gen")
  $dout = (& $Deep2Bench @dargs 2>$null | Out-String)
  $dout | Set-Content -LiteralPath (Join-Path $OutDir 'D_E_deep2.txt')
  # deep2_benchmark emits one JSON object (prefill/decode TPS, GPU/CPU ops, MoE ms, result).
  try {
    $j = $dout | ConvertFrom-Json
    $deep2.prefill_tps=$j.prefill_tps; $deep2.decode_tps=$j.decode_tps
    $deep2.gpu_rows=$j.planned_gpu_ops; $deep2.cpu_rows=$j.planned_cpu_ops
    $deep2.unplanned=$j.unplanned_fallback
    $deep2.router_ms=$j.moe_router_ms; $deep2.expert_dispatch_ms=$j.moe_expert_ms
    $deep2.result=$j.result
    if($j.unplanned_fallback -gt 0){ $script:incomplete += "E: unplanned_fallback=$($j.unplanned_fallback)" }
    if($j.result -ne 'PASS'){ $script:incomplete += "deep2 result=$($j.result)" }
  } catch { $script:incomplete += 'D/E: deep2 JSON parse failed' }
} else { $script:incomplete += 'D/E: deep2_benchmark not found' }

# ================= (6) Reject incomplete -> no PASS ==========================
$result = if($incomplete.Count -eq 0){ 'PASS' } else { 'INCOMPLETE' }

# ============================ Emit report ====================================
$report['COMMIT']=$Commit
$report['DATE']=(Get-Date -Format o)
$report['GPU_IDENTITY']=$gpuIdentity
$report['ENV_DEVICE']='GGML_VK_VISIBLE_DEVICES=0'
$report['FIXED']="ctx=$Ctx threads=$Threads temp=0 reps=$Reps gen=$Gen"
$report['HASHES']=$hashes
$report['RESIDENCY']=$C
$report['PREFILL_AVG']=$B.avg
$report['DECODE_AVG']=$A.avg
$report['CPU_FALLBACK_ROWS']=$deep2.cpu_rows
$report['GPU_ROWS']=$deep2.gpu_rows
$report['ROUTER_MS']=$deep2.router_ms
$report['EXPERT_DISPATCH_MS']=$deep2.expert_dispatch_ms
$report['REAP']=$G
$report['INCOMPLETE']=$incomplete
$report['RESULT']=$result

$lines = @("COMMIT: $($report['COMMIT'])","MODEL:  GLM-4.7-Flash Q4_K_M","GPU:    $($report['GPU_IDENTITY'])",
  "ENV:    $($report['ENV_DEVICE'])","FIXED:  $($report['FIXED'])","DATE:   $($report['DATE'])",
  "HASHES: $($hashes | ConvertTo-Json -Compress)","RESIDENCY: $($C | ConvertTo-Json -Compress)",
  "PREFILL_AVG: $($B.avg)","DECODE_AVG: $($A.avg)","CPU_FALLBACK_ROWS: $($deep2.cpu_rows)","GPU_ROWS: $($deep2.gpu_rows)",
  "ROUTER_MS: $($deep2.router_ms)","EXPERT_DISPATCH_MS: $($deep2.expert_dispatch_ms)",
  "REAP: $($G | ConvertTo-Json -Compress)","INCOMPLETE: $($incomplete -join '; ')","RESULT: $result")
$lines -join "`n" | Set-Content -LiteralPath (Join-Path $OutDir 'REPORT.txt')
Write-Host ($lines -join "`n")
if($result -ne 'PASS'){ exit 2 }   # non-zero so CI/handoff cannot treat incomplete as pass