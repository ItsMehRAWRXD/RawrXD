# run_parity_cert_001.ps1 — PARITY-CERT-001 orchestrator
#
# Deep2: zero inference deps (no Ollama / no llama linked into Deep2).
# Reference: EXTERNAL llama.cpp measuring-stick process only.
#
# Forces: temperature=0, top_k=1, max_new_tokens=15, prompt=hello
# Do NOT use compare_llamacpp_rawrxd.ps1 defaults (temp 0.8 / top_k 40).

[CmdletBinding()]
param(
    [string]$Repo = "F:\~dev\rawrxd",
    [string]$Model = "F:\~dev\tinyllama_fresh.gguf",
    [string]$Prompt = "hello",
    [int]$MaxNewTokens = 15,
    [string]$Deep2Exe = "",
    [string]$RefExe = "",
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
if ([string]::IsNullOrWhiteSpace($RefExe)) {
    $RefExe = Join-Path $Repo "tools\parity_ref\bin\llama_ref_parity_probe.exe"
}

function Parse-IdList([string]$text, [string]$key) {
    $line = ($text -split "`r?`n" | Where-Object { $_ -like "$key=*" } | Select-Object -First 1)
    if (-not $line) { return @() }
    $v = $line.Substring($key.Length + 1).Trim()
    if ([string]::IsNullOrWhiteSpace($v)) { return @() }
    return @($v.Split(',') | ForEach-Object { [int]$_ })
}

Write-Host "=== PARITY-CERT-001 ==="
Write-Host "canonical_repo=$Repo"
Write-Host "model=$Model"
Write-Host "prompt=$Prompt max_new_tokens=$MaxNewTokens temperature=0 top_k=1"
Write-Host "deep2_backend=Deep2 (deps=NONE)"
Write-Host "reference_backend=llama.cpp (external measuring stick ONLY)"

if (!(Test-Path $Deep2Exe)) {
    Write-Host "Deep2 parity exe missing: $Deep2Exe"
    Write-Host "Build: cmake --build build-ninja --target deep2_parity_cert"
    exit 10
}
if (!(Test-Path $RefExe)) {
    Write-Host "Reference probe missing: $RefExe"
    Write-Host "Build: powershell -File tools\parity_ref\build_llama_ref_probe.ps1"
    exit 11
}

$deep2Out = Join-Path $OutDir "deep2.stdout.txt"
$deep2Err = Join-Path $OutDir "deep2.stderr.txt"
$refOut = Join-Path $OutDir "ref.stdout.txt"
$refErr = Join-Path $OutDir "ref.stderr.txt"
$verdict = Join-Path $OutDir "PARITY_CERT_VERDICT.txt"

Remove-Item $deep2Out, $deep2Err, $refOut, $refErr, $verdict -ErrorAction SilentlyContinue

Write-Host "[1/2] Deep2 (sovereign, no llama/Ollama deps)..."
$d = Start-Process -FilePath $Deep2Exe -ArgumentList @($Model) `
    -WorkingDirectory (Split-Path $Deep2Exe) `
    -NoNewWindow -PassThru -Wait `
    -RedirectStandardOutput $deep2Out -RedirectStandardError $deep2Err
Write-Host "  deep2_exit=$($d.ExitCode)"

Write-Host "[2/2] llama.cpp measuring stick (external process)..."
$r = Start-Process -FilePath $RefExe -ArgumentList @($Model, $Prompt, "$MaxNewTokens") `
    -WorkingDirectory (Split-Path $RefExe) `
    -NoNewWindow -PassThru -Wait `
    -RedirectStandardOutput $refOut -RedirectStandardError $refErr
Write-Host "  ref_exit=$($r.ExitCode)"

$deep2Text = Get-Content $deep2Out -Raw -ErrorAction SilentlyContinue
$refText = Get-Content $refOut -Raw -ErrorAction SilentlyContinue

$deep2Prompt = Parse-IdList $deep2Text "DEEP2_PROMPT_IDS"
$refPrompt = Parse-IdList $refText "REF_PROMPT_IDS"
$deep2Gen = Parse-IdList $deep2Text "DEEP2_GEN_IDS"
$refGen = Parse-IdList $refText "REF_GEN_IDS"

$promptMatch = ($deep2Prompt.Count -gt 0) -and ($deep2Prompt.Count -eq $refPrompt.Count)
if ($promptMatch) {
    for ($i = 0; $i -lt $deep2Prompt.Count; $i++) {
        if ($deep2Prompt[$i] -ne $refPrompt[$i]) { $promptMatch = $false; break }
    }
}

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("PARITY-CERT-001") | Out-Null
$lines.Add("model=$Model") | Out-Null
$lines.Add("prompt=$Prompt") | Out-Null
$lines.Add("max_new_tokens=$MaxNewTokens") | Out-Null
$lines.Add("temperature=0") | Out-Null
$lines.Add("top_k=1") | Out-Null
$lines.Add("deep2_backend=Deep2") | Out-Null
$lines.Add("deep2_inference_deps=NONE") | Out-Null
$lines.Add("reference_backend=llama.cpp") | Out-Null
$lines.Add("reference_role=external_measuring_stick_only") | Out-Null
$lines.Add("DEEP2_PROMPT_IDS=$(($deep2Prompt -join ','))") | Out-Null
$lines.Add("REF_PROMPT_IDS=$(($refPrompt -join ','))") | Out-Null
$lines.Add("prompt_ids_match=$(if ($promptMatch) {'PASS'} else {'FAIL'})") | Out-Null
$lines.Add("") | Out-Null
$lines.Add("index deep2_id ref_id match") | Out-Null

$firstMismatch = -1
$count = [Math]::Max($deep2Gen.Count, $refGen.Count)
$count = [Math]::Min($count, $MaxNewTokens)
if ($deep2Gen.Count -eq 0 -or $refGen.Count -eq 0) {
    $firstMismatch = 0
}
for ($i = 0; $i -lt $MaxNewTokens; $i++) {
    $dId = if ($i -lt $deep2Gen.Count) { $deep2Gen[$i] } else { -1 }
    $rId = if ($i -lt $refGen.Count) { $refGen[$i] } else { -1 }
    $ok = ($dId -ge 0) -and ($dId -eq $rId)
    if (-not $ok -and $firstMismatch -lt 0) { $firstMismatch = $i }
    $lines.Add(("{0,-5} {1,-8} {2,-8} {3}" -f $i, $dId, $rId, $(if ($ok) {'PASS'} else {'FAIL'}))) | Out-Null
    if (-not $ok) { break }  # first mismatch only
}

$lines.Add("") | Out-Null
$lines.Add("first_mismatch=$firstMismatch") | Out-Null
$lines.Add("token_count=$MaxNewTokens") | Out-Null

if ($firstMismatch -eq 0) {
    $lines.Add("") | Out-Null
    $lines.Add("first_mismatch_index=0") | Out-Null
    $lines.Add("Deep2 token ID=$(if ($deep2Gen.Count -gt 0) {$deep2Gen[0]} else {'NA'})") | Out-Null
    $lines.Add("reference token ID=$(if ($refGen.Count -gt 0) {$refGen[0]} else {'NA'})") | Out-Null
    $refTop = ($refText -split "`r?`n" | Where-Object { $_ -like "REF_TOP10=*" } | Select-Object -First 1)
    $refSel = ($refText -split "`r?`n" | Where-Object { $_ -like "REF_SELECTED_*" })
    $lines.Add("reference top-10 logits:") | Out-Null
    if ($refTop) { $lines.Add($refTop) | Out-Null }
    foreach ($s in $refSel) { $lines.Add($s) | Out-Null }
    $lines.Add("Deep2 top-10 logits: see deep2.stderr.txt / deep2.stdout.txt ([Deep2Engine] Top-10 logits)") | Out-Null
    $lines.Add("NEXT_STAGE_TRACE=tokenizer->embedding->layer0_input->attn_norm->QKV->attn_out->FFN->residual->final_hidden->final_RMSNorm->LM_head") | Out-Null
    $lines.Add("Use norms/hashes first; dump vectors only at first divergence.") | Out-Null
}

$certified = ($promptMatch -and $firstMismatch -lt 0 -and $deep2Gen.Count -ge $MaxNewTokens -and $refGen.Count -ge $MaxNewTokens)
# Allow early EOS if both sides match through min length and firstMismatch < 0
if ($promptMatch -and $firstMismatch -lt 0 -and $deep2Gen.Count -gt 0 -and $deep2Gen.Count -eq $refGen.Count) {
    $certified = $true
}

if ($certified) {
    $lines.Add("RAWRXD_DEEP2_PARITY=CERTIFIED") | Out-Null
} else {
    $lines.Add("RAWRXD_DEEP2_PARITY=FAILED") | Out-Null
}

$lines | Set-Content -Encoding utf8 $verdict
$lines | ForEach-Object { Write-Host $_ }

if ($certified) { exit 0 } else { exit 30 }
