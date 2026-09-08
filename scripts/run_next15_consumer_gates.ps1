# run_next15_consumer_gates.ps1 — B2,B4-B8,C2-C9,A1 in order
$ErrorActionPreference = "Continue"
$Bin = "G:\~dev\rawrxd\build-fd\bin"
$Evid = "G:\~dev\rawrxd\evidence"
$K2 = "F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M"
$Tiny = "G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"

function Seal-Gate([string]$name, [string]$body) {
    $dir = Join-Path $Evid $name
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    # UTF-8 no BOM — C9 ReadGatePass is narrow-char getline
    $path = Join-Path $dir "GATE_STATUS.txt"
    [System.IO.File]::WriteAllText($path, ($body -replace "`r`n","`n").TrimEnd() + "`r`n",
        [System.Text.UTF8Encoding]::new($false))
}

function Run-Exe([string]$exe, [string]$gate, [string[]]$extraArgs = @()) {
    $path = Join-Path $Bin $exe
    if (!(Test-Path $path)) {
        Write-Host "MISSING $exe"
        Seal-Gate $gate "$gate=FAIL`nMISSING_EXE=1`n"
        return "FAIL"
    }
    Write-Host "`n==== $gate ($exe) ===="
    $out = & $path @extraArgs 2>&1 | Out-String
    Write-Host $out
    $pass = $out -match ("(?m)" + [regex]::Escape($gate) + "=PASS")
    if (-not $pass -and $gate -eq "VWA_COALESCE_001") {
        $pass = $out -match "VWA_FILE_COALESCE_001=PASS"
    }
    $status = if ($pass) { "PASS" } else { "FAIL" }
    Seal-Gate $gate ($out + "`n$gate=$status`n")
    return $status
}

$gates = @(
    @{ Gate = "VWA_COALESCE_001"; Exe = "deep2_vwa_file_coalesce_001.exe" },
    @{ Gate = "VWA_ELASTIC_RANGE_001"; Exe = "deep2_vwa_elastic_range_001.exe" },
    @{ Gate = "VWA_EXPERT_SLICE_001"; Exe = "deep2_vwa_expert_slice_001.exe" },
    @{ Gate = "VWA_MOE_PREFETCH_001"; Exe = "deep2_vwa_moe_prefetch_001.exe" },
    @{ Gate = "VWA_GPU_STAGE_001"; Exe = "deep2_vwa_gpu_stage_001.exe" },
    @{ Gate = "VWA_BOUNDED_K2_001"; Exe = "deep2_vwa_bounded_k2_001.exe" },
    @{ Gate = "K2_LOGITS_RANGE_SWEEP_001"; Exe = "deep2_k2_logits_range_sweep_001.exe" },
    @{ Gate = "K2_LOGITS_RANGE_FREEZE_001"; Exe = "deep2_k2_logits_range_freeze_001.exe" },
    @{ Gate = "VWA_ASYNC_FILE_RANGE_001"; Exe = "deep2_vwa_async_file_range_001.exe" },
    @{ Gate = "VWA_GPU_TRANSFER_001"; Exe = "deep2_vwa_gpu_transfer_001.exe" },
    @{ Gate = "VWA_K2_EXPERT_SELECTIVE_001"; Exe = "deep2_vwa_k2_expert_selective_001.exe" },
    @{ Gate = "VWA_K2_PREFETCH_OVERLAP_001"; Exe = "deep2_vwa_k2_prefetch_overlap_001.exe" },
    @{ Gate = "VWA_BOUNDED_K2_001_C8"; Exe = "deep2_vwa_bounded_k2_001.exe"; Alias = "VWA_BOUNDED_K2_001" },
    @{ Gate = "VWA_K2_FULL_E2E_001"; Exe = "deep2_vwa_k2_full_e2e_001.exe" },
    @{ Gate = "LOCAL_AGENT_AUDIT_001"; Exe = "deep2_local_agent_audit_001.exe" }
)

# Also seal B3 if runnable
if (Test-Path (Join-Path $Bin "deep2_vwa_iocp_range_001.exe")) {
    $null = Run-Exe "deep2_vwa_iocp_range_001.exe" "VWA_IOCP_RANGE_001"
}

$results = @()
foreach ($g in $gates) {
    $gateName = if ($g.Alias) { $g.Alias } else { $g.Gate }
    if ($g.Gate -eq "VWA_BOUNDED_K2_001_C8") {
        # C8 shares B8 binary; evidence already written — re-seal as C8 copy
        $src = Join-Path $Evid "VWA_BOUNDED_K2_001\GATE_STATUS.txt"
        if (Test-Path $src) {
            Seal-Gate "VWA_BOUNDED_K2_001" (Get-Content $src -Raw)
            $results += "C8/B8 VWA_BOUNDED_K2_001=already"
        }
        continue
    }
    if ($gateName -eq "LOCAL_AGENT_AUDIT_001") {
        $env:DEEP2_AUDIT_MODEL = $Tiny
        $env:DEEP2_K2_SHARD_DIR = $K2
    }
    $st = Run-Exe $g.Exe $gateName
    $results += "$gateName=$st"
}

Write-Host "`n==== NEXT15 SUMMARY ===="
$results | ForEach-Object { Write-Host $_ }
