# F:\rawrxd-native-agent-001\capture_oracle_vectors.ps1
# Gate 2 oracle capture: non-REPL prompt file only; fail-closed seal.
# CAPTURE=SEALED != GATE2_PARITY_READY. PROMOTE=0. NOT_RUN!=PASS.
$ErrorActionPreference = "Stop"

$BinDir      = "F:\llama.cpp-ref\build\bin"
$EngineCli   = Join-Path $BinDir "llama-cli.exe"
$EngineComp  = Join-Path $BinDir "llama-completion.exe"
$Model       = "F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf"
$Corpus      = "F:\rawrxd-native-agent-001\corpus.jsonl"
$FactoryTool = "F:\rawrxd\build_ide\bin-msvc\reap-reference-receipt.exe"
$EvidenceDir = "F:\rawrxd-native-agent-001\evidence"
$ReceiptOut  = Join-Path $EvidenceDir "independent_reference_receipt.json"
$TraceFile   = Join-Path $EvidenceDir "oracle_raw_trace.log"
$PromptFile  = Join-Path $EvidenceDir "oracle_continuous_prompt.txt"
$BlockerFile = Join-Path $EvidenceDir "GATE2_REFERENCE_VECTOR_BLOCKER.txt"
$EngineVer   = "0.7.0-dev-961c376"
$NPredict    = 256

# Prefer non-REPL completion tool; fall back to llama-cli only if completion absent.
$Engine = $null
$EngineKind = ""
if (Test-Path -LiteralPath $EngineComp) {
    $Engine = $EngineComp
    $EngineKind = "llama-completion"
} elseif (Test-Path -LiteralPath $EngineCli) {
    $Engine = $EngineCli
    $EngineKind = "llama-cli"
} else {
    throw "MISSING: neither llama-completion.exe nor llama-cli.exe under $BinDir"
}

foreach ($p in @($Model, $Corpus, $FactoryTool)) {
    if (-not (Test-Path -LiteralPath $p)) { throw "MISSING: $p" }
}
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null

function Write-Blocker([string]$msg) {
    $body = @(
        "GATE2=BLOCKED_INVALID_REFERENCE_VECTORS"
        "RECEIPT_VECTORS_VALID=0"
        "REFERENCE_PARITY=NOT_RUN"
        "CALIBRATION_COMPLETE=0"
        "PROMOTE=0"
        "TIP_CLIMB=HOLD"
        "ENGINE_KIND=$EngineKind"
        "ENGINE=$Engine"
        "NOT_RUN!=PASS"
        "BLOCKER=$msg"
        "NEXT=Build/obtain non-REPL tool that emits integer token ids (llama-completion + id dump, or server return_tokens); re-capture; then continuous --parity"
    ) -join "`r`n"
    [System.IO.File]::WriteAllText($BlockerFile, $body)
    Write-Host $body
}

Write-Host "Initializing zero-variance capture (prompt.front only; fail-closed seal)..."
Write-Host "ENGINE_KIND=$EngineKind ENGINE=$Engine"

# Extract corpus prompts.front() -> oracle_continuous_prompt.txt (must feed -f this file).
$firstLine = Get-Content -LiteralPath $Corpus -TotalCount 1 -ErrorAction Stop
$m = [regex]::Match($firstLine, '"text"\s*:\s*"(.*?)",\s*"domain"')
if (-not $m.Success) {
    Write-Blocker "CORPUS_FRONT_TEXT_PARSE_FAILED"
    Write-Error "Cannot parse corpus prompts.front() text"
    exit 2
}
$promptText = [System.Text.RegularExpressions.Regex]::Unescape($m.Groups[1].Value)
[System.IO.File]::WriteAllText($PromptFile, $promptText)
Write-Host "CORPUS_FRONT_PROMPT_CHARS=$($promptText.Length) PROMPT_FILE=$PromptFile"

# Non-interactive completion flags. Do NOT feed whole corpus.jsonl.
# llama-cli (this tree): no --no-conversation; use --no-jinja --single-turn.
# llama-completion: -no-cnv / --no-conversation when present.
$argList = New-Object System.Collections.Generic.List[string]
[void]$argList.AddRange([string[]]@(
    "-m", $Model,
    "-f", $PromptFile,
    "-c", "2048",
    "-n", "$NPredict",
    "--temp", "0",
    "--top-k", "1",
    "--top-p", "1.0",
    "--min-p", "0.0",
    "--repeat-penalty", "1.0",
    "--seed", "0",
    "--ignore-eos",
    "--no-display-prompt"
))
if ($EngineKind -eq "llama-completion") {
    [void]$argList.Add("-no-cnv")
} else {
    [void]$argList.Add("--no-jinja")
    [void]$argList.Add("--single-turn")
}

$TokenDumpFile = Join-Path $EvidenceDir "oracle_generated_token_ids.txt"
if (Test-Path -LiteralPath $TokenDumpFile) { Remove-Item -LiteralPath $TokenDumpFile -Force }
$env:RAWRXD_ORACLE_TOKEN_DUMP = $TokenDumpFile

Write-Host "ORACLE_CMD=$Engine $($argList -join ' ')"
Write-Host "RAWRXD_ORACLE_TOKEN_DUMP=$TokenDumpFile"
$stdoutFile = Join-Path $EvidenceDir "oracle_stdout.log"
$stderrFile = Join-Path $EvidenceDir "oracle_stderr.log"
$proc = Start-Process -FilePath $Engine -ArgumentList $argList.ToArray() -NoNewWindow -PassThru -Wait `
    -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile
$combined = (Get-Content -LiteralPath $stdoutFile -Raw -ErrorAction SilentlyContinue) + "`n" +
            (Get-Content -LiteralPath $stderrFile -Raw -ErrorAction SilentlyContinue)
[System.IO.File]::WriteAllText($TraceFile, $combined)
Write-Host "ORACLE_EXIT=$($proc.ExitCode) TRACE=$TraceFile"

# Parse timings + integer token ids only (no invented ids).
$PromptCount = 0
$PredictedN = 0
$TokenIds = New-Object System.Collections.Generic.List[int]
$v = 0
$sawTokensArray = $false
$tokensArrayEmpty = $false

# Preferred: atomic sidecar from patched llama-completion (avoids async stderr shred).
if (Test-Path -LiteralPath $TokenDumpFile) {
    Get-Content -LiteralPath $TokenDumpFile | ForEach-Object {
        $line = $_
        if ($line -match '^PROMPT_TOKENS=(\d+)\s*$') {
            $n = 0
            if ([int]::TryParse($Matches[1], [ref]$n) -and $n -gt 0) { $PromptCount = $n }
        }
        if ($line -match '^GENERATED_TOKEN_IDS=(.+)$') {
            $TokenIds.Clear()
            foreach ($tok in ($Matches[1] -split ",")) {
                $t = $tok.Trim()
                if ($t -ne "" -and [int]::TryParse($t, [ref]$v)) { [void]$TokenIds.Add($v) }
            }
            if ($TokenIds.Count -gt 0) { $PredictedN = $TokenIds.Count }
        }
    }
    Write-Host "SIDECAR_DUMP=$TokenDumpFile PROMPT=$PromptCount IDS=$($TokenIds.Count)"
}

Get-Content -LiteralPath $TraceFile | ForEach-Object {
    $line = $_
    # Fallback: patched llama-completion dump lines in combined trace.
    if ($PromptCount -le 0 -and $line -match '^PROMPT_TOKENS=(\d+)\s*$') {
        $n = 0
        if ([int]::TryParse($Matches[1], [ref]$n) -and $n -gt 0) { $PromptCount = $n }
    }
    if ($TokenIds.Count -eq 0 -and $line -match '^GENERATED_TOKEN_IDS=(.+)$') {
        $TokenIds.Clear()
        foreach ($tok in ($Matches[1] -split ",")) {
            $t = $tok.Trim()
            if ($t -ne "" -and [int]::TryParse($t, [ref]$v)) { [void]$TokenIds.Add($v) }
        }
        if ($TokenIds.Count -gt 0) { $PredictedN = $TokenIds.Count }
    }
    if ($line -match '"prompt_n"\s*:\s*(\d+)') {
        $n = 0
        if ([int]::TryParse($Matches[1], [ref]$n) -and $n -gt 0 -and $PromptCount -le 0) { $PromptCount = $n }
    }
    if ($line -match '"predicted_n"\s*:\s*(\d+)') {
        $n = 0
        if ([int]::TryParse($Matches[1], [ref]$n) -and $n -gt $PredictedN) { $PredictedN = $n }
    }
    if ($line -match '"tokens"\s*:\s*\[(.*?)\]') {
        $sawTokensArray = $true
        $inner = $Matches[1].Trim()
        if ($inner -eq "") {
            $tokensArrayEmpty = $true
        } elseif ($TokenIds.Count -eq 0) {
            foreach ($tok in ($inner -split ",")) {
                $t = $tok.Trim()
                if ($t -ne "" -and [int]::TryParse($t, [ref]$v)) { [void]$TokenIds.Add($v) }
            }
        }
    }
    if ($TokenIds.Count -eq 0 -and (
        $line -match "sampled token[:\s]+id\s*=\s*(\d+)" -or
        $line -match "sampled token\s*:\s*(\d+)" -or
        $line -match "^\s*(\d+)\s*->\s*'")) {
        if ([int]::TryParse($Matches[1], [ref]$v)) { [void]$TokenIds.Add($v) }
    }
}

function Test-SpecialTokenSpam($ids) {
    if ($null -eq $ids -or $ids.Count -eq 0) { return $true }
    $spam = 0
    foreach ($id in $ids) {
        if ($id -eq 100000 -or $id -eq 100001 -or $id -eq 185) { $spam++ }
    }
    return ($spam -ge [Math]::Max(1, [int][Math]::Floor($ids.Count * 0.75)))
}

Write-Host "PROMPT_N=$PromptCount PREDICTED_N=$PredictedN GENERATED_IDS=$($TokenIds.Count) TOKENS_ARRAY_SEEN=$sawTokensArray TOKENS_ARRAY_EMPTY=$tokensArrayEmpty"

# Fail-closed seal gates
if ($TokenIds.Count -eq 0) {
    Write-Blocker "NO_INTEGER_TOKEN_IDS engine=$EngineKind; stream tokens=[] empty or absent; REPL/chat-server text-only. llama-completion.exe not in bin."
    Write-Error "RECEIPT_VECTORS_VALID=0 - refuse seal (no integer token ids)."
    exit 3
}
if ($TokenIds.Count -ne $NPredict) {
    Write-Blocker "TOKEN_IDS_COUNT=$($TokenIds.Count) != N_PREDICT=$NPredict (also predicted_n=$PredictedN)"
    Write-Error "RECEIPT_VECTORS_VALID=0 - refuse seal (count != predicted window)."
    exit 4
}
if ($PromptCount -le 0) {
    Write-Blocker "PROMPT_TOKENS_MISSING from timings (need prompt_n)"
    Write-Error "RECEIPT_VECTORS_VALID=0 - refuse seal (prompt_tokens missing)."
    exit 5
}
if ($PredictedN -gt 0 -and $PromptCount -gt 0 -and $PredictedN -ne $NPredict -and $TokenIds.Count -ne $PredictedN) {
    Write-Blocker "PREDICTED_N=$PredictedN mismatch vs N_PREDICT=$NPredict / ids=$($TokenIds.Count)"
    Write-Error "RECEIPT_VECTORS_VALID=0 - refuse seal (predicted_n mismatch)."
    exit 6
}
if (Test-SpecialTokenSpam $TokenIds) {
    Write-Blocker "SPECIAL_TOKEN_SPAM ids look like 100000/100001/185 parse artifacts; count=$($TokenIds.Count)"
    Write-Error "RECEIPT_VECTORS_VALID=0 - refuse seal (special-token spam)."
    exit 7
}

$CsvTokens = ($TokenIds -join ",")
Write-Host "PROMPT_TOKENS=$PromptCount GENERATED_IDS=$($TokenIds.Count) - sealing via factory"

& $FactoryTool $Engine $Model $Corpus "$PromptCount" $CsvTokens $EngineVer $ReceiptOut
if ($LASTEXITCODE -ne 0) {
    Write-Error "FACTORY_EXIT=$LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host "REFERENCE_RECEIPT=$ReceiptOut"
Write-Host "RECEIPT_VECTORS_VALID=1 (structural+vectors); GATE2 still requires continuous --parity"
Write-Host "PROMOTE=0 TIP_CLIMB=HOLD NOT_RUN!=PASS"
