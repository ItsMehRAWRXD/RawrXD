param(
    [Parameter(Mandatory=$true)][string]$Exe,
    [Parameter(Mandatory=$true)][string]$ModelsRoot,
    [string]$OutDir = ".\parity_receipts",
    [string]$Prompt = "The meaning of life is",
    [int]$Steps = 8
)
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$models = Get-ChildItem -Path $ModelsRoot -Recurse -File -Filter *.gguf
if (!$models) { throw "No GGUF files under $ModelsRoot" }

$pass=0; $fail=0
foreach($m in $models) {
    $safe = ($m.BaseName -replace '[^A-Za-z0-9_.-]','_')
    $dir = Join-Path $OutDir $safe
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $receipt = Join-Path $dir "receipt.txt"
    $cpu = Join-Path $dir "cpu.trace"
    $gpu = Join-Path $dir "gpu.trace"
    Write-Host "=== $($m.FullName) ==="
    & $Exe --model $m.FullName --prompt $Prompt --steps $Steps `
        --receipt $receipt --cpu-trace $cpu --gpu-trace $gpu
    if ($LASTEXITCODE -eq 0) { ++$pass } else { ++$fail }
}
"MODELS_PASS=$pass" | Set-Content (Join-Path $OutDir "aggregate.txt")
"MODELS_FAIL=$fail" | Add-Content (Join-Path $OutDir "aggregate.txt")
"VERDICT=$(if($fail -eq 0){'PASS'}else{'FAIL'})" | Add-Content (Join-Path $OutDir "aggregate.txt")
Write-Host "PASS=$pass FAIL=$fail"
exit $(if($fail -eq 0){0}else{1})
