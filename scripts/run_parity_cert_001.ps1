# run_parity_cert_001.ps1 — PARITY-CERT-001 orchestrator (FROZEN_GOLDEN)
#
# Certification run = Deep2-only replay against offline golden_tokens.json.
# No llama.cpp / Ollama / other reference runtime may participate here.
# Do NOT invent golden token IDs from Deep2 output.

[CmdletBinding()]
param(
    [string]$Repo = "F:\~dev\rawrxd",
    [string]$Model = "F:\~dev\tinyllama_fresh.gguf",
    [string]$Prompt = "hello",
    [int]$MaxNewTokens = 15,
    [string]$Deep2Exe = "",
    [string]$OutDir = ""
)

$ErrorActionPreference = 'Stop'
Set-Location $Repo

if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $Repo "evidence\PARITY_CERT_001"
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

if ([string]::IsNullOrWhiteSpace($Deep2Exe)) {
    $Deep2Exe = Join-Path $Repo "build-ninja\bin\deep2_parity_cert.exe"
}

$goldenPath = Join-Path $OutDir "golden_tokens.json"
$verdict = Join-Path $OutDir "PARITY_CERT_VERDICT.txt"
$contract = Join-Path $OutDir "GOLDEN_DUMP_CONTRACT.txt"

function Parse-IdList([string]$text, [string]$key) {
    $line = ($text -split "`r?`n" | Where-Object { $_ -like "$key=*" } | Select-Object -First 1)
    if (-not $line) { return @() }
    $v = $line.Substring($key.Length + 1).Trim()
    if ([string]::IsNullOrWhiteSpace($v)) { return @() }
    return @($v.Split(',') | ForEach-Object { [int]$_ })
}

function Ids-Equal([int[]]$a, [int[]]$b) {
    if ($null -eq $a -or $null -eq $b) { return $false }
    if ($a.Count -ne $b.Count) { return $false }
    for ($i = 0; $i -lt $a.Count; $i++) {
        if ([int]$a[$i] -ne [int]$b[$i]) { return $false }
    }
    return $true
}

Write-Host "=== PARITY-CERT-001 ==="
Write-Host "canonical_repo=$Repo"
Write-Host "model=$Model"
Write-Host "prompt=$Prompt max_new_tokens=$MaxNewTokens temperature=0 top_k=1"
Write-Host "reference_mode=FROZEN_GOLDEN"
Write-Host "deep2_backend=Deep2 (deps=NONE)"
Write-Host "live_external_runtime_required=false"

if (!(Test-Path -LiteralPath $goldenPath)) {
    @"
PARITY-CERT-001
status=AWAITING_TRUSTED_GOLDEN
reference_mode=FROZEN_GOLDEN
RAWRXD_DEEP2_PARITY=NOT_CERTIFIED
reason=golden_tokens.json missing
contract=$contract
"@ | Set-Content -Encoding utf8 $verdict
    Write-Host "RAWRXD_DEEP2_PARITY=NOT_CERTIFIED (golden missing)"
    exit 20
}

$golden = Get-Content -LiteralPath $goldenPath -Raw | ConvertFrom-Json
if ($golden.status -eq "AWAITING_TRUSTED_DUMP" -or
    -not $golden.prompt_token_ids -or $golden.prompt_token_ids.Count -eq 0 -or
    -not $golden.generated_token_ids -or $golden.generated_token_ids.Count -eq 0) {
    @"
PARITY-CERT-001
status=AWAITING_TRUSTED_GOLDEN
reference_mode=FROZEN_GOLDEN
RAWRXD_DEEP2_PARITY=NOT_CERTIFIED
reason=golden_tokens.json has status=AWAITING_TRUSTED_DUMP; no trusted frozen reference artifact bound yet.
note=STREAMER-CERT-001=CERTIFIED and LIFECYCLE-CERT-001=CERTIFIED do not establish numerical inference parity.
next=Import independent offline golden into golden_tokens.json per GOLDEN_DUMP_CONTRACT.txt, then re-run this script (Deep2-only).
"@ | Set-Content -Encoding utf8 $verdict
    Get-Content $verdict | ForEach-Object { Write-Host $_ }
    exit 21
}

if (!(Test-Path -LiteralPath $Deep2Exe)) {
    Write-Host "Deep2 parity exe missing: $Deep2Exe"
    Write-Host "Build: cmake --build build-ninja --target deep2_parity_cert"
    exit 10
}

$deep2Out = Join-Path $OutDir "deep2.stdout.txt"
$deep2Err = Join-Path $OutDir "deep2.stderr.txt"
Remove-Item $deep2Out, $deep2Err, $verdict -ErrorAction SilentlyContinue

Write-Host "[1/1] Deep2 replay vs frozen golden (no live reference)..."
$d = Start-Process -FilePath $Deep2Exe -ArgumentList @($Model) `
    -WorkingDirectory (Split-Path $Deep2Exe) `
    -NoNewWindow -PassThru -Wait `
    -RedirectStandardOutput $deep2Out -RedirectStandardError $deep2Err
Write-Host "  deep2_exit=$($d.ExitCode)"

$deep2Text = Get-Content $deep2Out -Raw -ErrorAction SilentlyContinue
$deep2Prompt = @(Parse-IdList $deep2Text "DEEP2_PROMPT_IDS")
$deep2Gen = @(Parse-IdList $deep2Text "DEEP2_GEN_IDS")
$refPrompt = @($golden.prompt_token_ids | ForEach-Object { [int]$_ })
$refGen = @($golden.generated_token_ids | ForEach-Object { [int]$_ })

$promptMatch = Ids-Equal $deep2Prompt $refPrompt

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("PARITY-CERT-001") | Out-Null
$lines.Add("model=$Model") | Out-Null
$lines.Add("prompt=$Prompt") | Out-Null
$lines.Add("max_new_tokens=$MaxNewTokens") | Out-Null
$lines.Add("temperature=0") | Out-Null
$lines.Add("top_k=1") | Out-Null
$lines.Add("deep2_backend=Deep2") | Out-Null
$lines.Add("deep2_inference_deps=NONE") | Out-Null
$lines.Add("reference_mode=FROZEN_GOLDEN") | Out-Null
$lines.Add("live_external_runtime_required=false") | Out-Null
$lines.Add("DEEP2_PROMPT_IDS=$(($deep2Prompt -join ','))") | Out-Null
$lines.Add("GOLDEN_PROMPT_IDS=$(($refPrompt -join ','))") | Out-Null
$lines.Add("prompt_ids_match=$(if ($promptMatch) {'PASS'} else {'FAIL'})") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("index deep2_id golden_id match") | Out-Null

$firstMismatch = -1
if ($deep2Gen.Count -eq 0 -or $refGen.Count -eq 0) {
    $firstMismatch = 0
}
$limit = [Math]::Min([Math]::Max($deep2Gen.Count, $refGen.Count), $MaxNewTokens)
for ($i = 0; $i -lt $limit; $i++) {
    $dId = if ($i -lt $deep2Gen.Count) { $deep2Gen[$i] } else { -1 }
    $rId = if ($i -lt $refGen.Count) { $refGen[$i] } else { -1 }
    $ok = ($dId -ge 0) -and ($dId -eq $rId)
    if (-not $ok -and $firstMismatch -lt 0) { $firstMismatch = $i }
    $lines.Add(("{0,-5} {1,-8} {2,-8} {3}" -f $i, $dId, $rId, $(if ($ok) {'PASS'} else {'FAIL'}))) | Out-Null
    if (-not $ok) { break }
}

$lines.Add("") | Out-Null
$lines.Add("first_mismatch=$firstMismatch") | Out-Null
$lines.Add("token_count=$MaxNewTokens") | Out-Null

$certified = ($promptMatch -and $firstMismatch -lt 0 -and $deep2Gen.Count -gt 0 -and $deep2Gen.Count -eq $refGen.Count)
if ($certified) {
    $lines.Add("RAWRXD_DEEP2_PARITY=CERTIFIED") | Out-Null
} else {
    $lines.Add("RAWRXD_DEEP2_PARITY=FAILED") | Out-Null
}

$lines | Set-Content -Encoding utf8 $verdict
$lines | ForEach-Object { Write-Host $_ }

if ($certified) { exit 0 } else { exit 30 }
