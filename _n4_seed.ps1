# N4 parity oracle seed run: strict rawr.exe vs ollama reference (same model, temp=0, seed=1)
# Gates: PROMPT_TOKEN_IDS_MATCH, LOGITS_FINITE, TOKEN_DECODE_VALID, DETERMINISTIC_REPEAT, COHERENT_RESPONSE
$ErrorActionPreference = "Continue"
$out = "F:\~dev\_n4_run.log"
"=== N4 SEED RUN $(Get-Date -Format HH:mm:ss) ===" | Out-File $out -Encoding UTF8

# 1. Ollama reference (raw API, temp=0 seed=1, byte-verified)
$refBody = @{
    model = "ministral3:latest"
    prompt = "hi"
    stream = $false
    options = @{ temperature = 0; seed = 1; num_predict = 6 }
} | ConvertTo-Json -Depth 4
try {
    $refRaw = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:11434/api/generate" -Method Post -Body $refBody -ContentType "application/json" -TimeoutSec 120
    $refJson = $refRaw.Content | ConvertFrom-Json
    "OLLAMA_RESPONSE=[$($refJson.response)]" | Out-File $out -Append -Encoding UTF8
    "OLLAMA_EVAL_COUNT=$($refJson.eval_count) PROMPT_EVAL=$($refJson.prompt_eval_count)" | Out-File $out -Append -Encoding UTF8
} catch {
    "OLLAMA_CALL=FAIL $($_.Exception.Message)" | Out-File $out -Append -Encoding UTF8
}

# 2. Strict-built rawr.exe (RAWRXD_MODEL_DIR set for G:\~dev)
$env:RAWRXD_MODEL_DIR = "G:\~dev"
$rawrOut = & "F:\~dev\rawrxd\build_clean_n1\bin\Release\rawr.exe" --tokens 6 ministral3_q4_0 "hi" 2>&1
$rawrOut | Out-File "F:\~dev\_n4_rawr_out.txt" -Encoding UTF8
"RAWR_EXIT=$LASTEXITCODE" | Out-File $out -Append -Encoding UTF8
($rawrOut | Select-Object -Last 8) | Out-File $out -Append -Encoding UTF8
"=== DONE ===" | Out-File $out -Append -Encoding UTF8
Get-Content $out