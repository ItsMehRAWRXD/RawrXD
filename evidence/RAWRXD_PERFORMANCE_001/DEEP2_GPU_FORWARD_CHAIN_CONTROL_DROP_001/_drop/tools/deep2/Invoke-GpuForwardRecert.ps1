param(
    [string]$Repo = "G:\~dev\rawrxd",
    [Parameter(Mandatory=$true)][string]$Exe,
    [Parameter(Mandatory=$true)][string]$Model,
    [string]$Prompt = "Write one short sentence."
)
$ErrorActionPreference="Stop"
Set-StrictMode -Version Latest

# This is intentionally conservative. It only performs the two single-model
# witnesses. The existing project multi-model matrix remains the authority for
# the final matrix re-seal and can be plugged in via -MatrixCommand later.

$outDir = Join-Path $Repo ("evidence\GPU_FORWARD_RECERT\" + (Get-Date -Format "yyyyMMdd_HHmmss"))
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$env:DEEP2_GPU_FORWARD_CHILD_IGNORE=""
$env:DEEP2_GPU_ISO_RUN="0"
$env:OLLAMA_HTTP="0"
$env:DEEP2_FORCE_PROMOTE="0"

foreach($n in @(20,64)) {
    $o=Join-Path $outDir "tok$n.stdout.txt"
    $e=Join-Path $outDir "tok$n.stderr.txt"
    $p=Start-Process -FilePath $Exe -ArgumentList @("--model",$Model,"--prompt",$Prompt,"--max-tokens","$n") `
       -Wait -PassThru -NoNewWindow -RedirectStandardOutput $o -RedirectStandardError $e
    if($p.ExitCode -ne 0){ throw "tok$n re-cert process exit $($p.ExitCode)" }
}
@(
 "RECERT_CONTROL=DEEP2_GPU_FORWARD_RECERT_001"
 "CONTROL_RUNTIME_AUTHORITY=0"
 "TOK20=EXECUTED"
 "TOK64=EXECUTED"
 "MULTI_MODEL_MATRIX=EXTERNAL_EXISTING_AUTHORITY"
 "PROMOTE=0"
) | Set-Content -Encoding UTF8 (Join-Path $outDir "RECERT_CONTROL.txt")
Write-Host "RECERT_EVIDENCE=$outDir"
