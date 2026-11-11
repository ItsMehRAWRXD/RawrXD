$ErrorActionPreference = 'Stop'
$outDir = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\issue49_candidate_D56FE6DD_928A90F0_001'
$sessPath = Join-Path $outDir 'bin\.rawrxd\ledger\agent_session.json'
$raw = Get-Content -Raw -LiteralPath $sessPath
$j = $raw | ConvertFrom-Json
$turns = @($j.turns)
"TURN_COUNT=$($turns.Count)" | Out-File -FilePath (Join-Path $outDir '_transcript_extract.txt') -Encoding utf8
foreach ($t in $turns) {
    $c = [string]$t.content
    "---`nrole=$($t.role) len=$($c.Length)" | Out-File -FilePath (Join-Path $outDir '_transcript_extract.txt') -Append -Encoding utf8
    if ($c -match 'RESPONSE_RECV|OLLAMA_AGENT_VERDICT|response_bytes|Task failed|\[fail\]') {
        $c | Out-File -FilePath (Join-Path $outDir '_transcript_extract.txt') -Append -Encoding utf8
    }
}

# Also dump OUTPUT_SAMPLE from 020 product final without truncation
$p020 = Join-Path $outDir 'issue49_gui_ollama_qwen3_020\issue49_product_final_74aa_20261110-094850.txt'
$lines = Get-Content -LiteralPath $p020
foreach ($line in $lines) {
    if ($line.StartsWith('OUTPUT_SAMPLE=')) {
        $line | Out-File -FilePath (Join-Path $outDir '_output_sample_020_full.txt') -Encoding utf8
        "OUTPUT_SAMPLE_LEN=$($line.Length)" | Out-File -FilePath (Join-Path $outDir '_output_sample_020_full.txt') -Append -Encoding utf8
    }
}

# Extract after RESPONSE_RECV from OUTPUT_SAMPLE if present
$os = Get-Content -Raw -LiteralPath (Join-Path $outDir '_output_sample_020_full.txt')
$idx = $os.IndexOf('RESPONSE_RECV')
if ($idx -ge 0) {
    $after = $os.Substring($idx)
    $after | Out-File -FilePath (Join-Path $outDir '_after_response_recv_020.txt') -Encoding utf8
    "AFTER_LEN=$($after.Length)" | Out-File -FilePath (Join-Path $outDir '_after_response_recv_020.txt') -Append -Encoding utf8
}

Write-Output 'OK'