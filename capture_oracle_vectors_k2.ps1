# F:\rawrxd-native-agent-001\capture_oracle_vectors_k2.ps1
# Gate 2 K2 retarget: llama-completion vs Kimi K2 multi-shard. Fail-closed.
# PROMOTE=0. TIP_CLIMB=HOLD. NOT_RUN!=PASS. Do not invent token ids.
$ErrorActionPreference = "Stop"

# Prefer Vulkan+mmap+cpu-moe path that previously reached decode progress (86/256 abort).
# Token dump requires llama-completion (RAWRXD_ORACLE_TOKEN_DUMP), not bare llama.exe cli.
$BinDirVulkan = "F:\llama.cpp-ref\build-vulkan\bin"
$BinDirCpu    = "F:\llama.cpp-ref\build\bin"
$BinDir       = $(if (Test-Path (Join-Path $BinDirVulkan "llama-completion.exe")) { $BinDirVulkan } else { $BinDirCpu })
$EngineComp  = Join-Path $BinDir "llama-completion.exe"
$Model       = "F:\OllamaModels\Kimi-K2-Instruct-0905-GGUF\Q4_K_M\Kimi-K2-Instruct-0905-Q4_K_M-00001-of-00013.gguf"
$Corpus      = "F:\rawrxd-native-agent-001\corpus.jsonl"
$FactoryTool = "F:\rawrxd\build_ide\bin-msvc\reap-reference-receipt.exe"
$EvidenceDir = "F:\rawrxd-native-agent-001\evidence"
$ReceiptOut  = Join-Path $EvidenceDir "independent_reference_receipt_k2.json"
$TraceFile   = Join-Path $EvidenceDir "oracle_k2_raw_trace.log"
# Official seal prompt (must hash-match first_corpus_prompt.txt); keep oracle_continuous as alias copy.
$PromptFile  = Join-Path $EvidenceDir "first_corpus_prompt.txt"
$PromptAlias = Join-Path $EvidenceDir "oracle_continuous_prompt.txt"
$BlockerFile = Join-Path $EvidenceDir "GATE2_K2_CAPTURE_BLOCKER.txt"
$MetaFile    = Join-Path $EvidenceDir "oracle_k2_capture_meta.txt"
$EngineVer   = "0.7.0-dev-961c376"
$NPredict    = 256

if (-not (Test-Path -LiteralPath $EngineComp)) { throw "MISSING: $EngineComp" }
$Engine = $EngineComp
$EngineKind = "llama-completion"

foreach ($p in @($Model, $Corpus, $FactoryTool)) {
    if (-not (Test-Path -LiteralPath $p)) { throw "MISSING: $p" }
}
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null

function Write-Blocker([string]$msg) {
    $body = @(
        "GATE2=BLOCKED_K2_CAPTURE"
        "K2_PATH=$Model"
        "CAPTURE=FAILED"
        "TOKEN_IDS_LEN=0"
        "RECEIPT=NOT_SEALED"
        "REPLAY_EXIT=NOT_RUN"
        "REFERENCE_PARITY=NOT_RUN"
        "CALIBRATION_COMPLETE=0"
        "PROMOTE=0"
        "TIP_CLIMB=HOLD"
        "ENGINE_KIND=$EngineKind"
        "ENGINE=$Engine"
        "NOT_RUN!=PASS"
        "BLOCKER=$msg"
        "NEXT=Provide machine with enough RAM/VRAM or quantized/stream-capable oracle for K2; re-run capture; then continuous --parity --require-mla. Do not weaken MLA-CERT-001."
    ) -join "`r`n"
    [System.IO.File]::WriteAllText($BlockerFile, $body)
    Write-Host $body
}

$os = Get-CimInstance Win32_OperatingSystem
$totalGB = [math]::Round($os.TotalVisibleMemorySize / 1MB, 1)
$freeGB  = [math]::Round($os.FreePhysicalMemory / 1MB, 1)
$shardGB = [math]::Round((Get-Item -LiteralPath $Model).Length / 1GB, 2)
$meta = @(
    "K2_PATH=$Model"
    "K2_FIRST_SHARD_GB=$shardGB"
    "HOST_RAM_TOTAL_GB=$totalGB"
    "HOST_RAM_FREE_GB=$freeGB"
    "PAGEFILE_MAX_MB=4096"
    "GPU=nvidia-smi_ABSENT"
    "ENGINE=$Engine"
    "N_PREDICT=$NPredict"
    "START=$(Get-Date -Format o)"
) -join "`r`n"
[System.IO.File]::WriteAllText($MetaFile, $meta)
Write-Host $meta

Write-Host "Initializing K2 zero-variance capture (prompt.front only; fail-closed seal)..."

$firstLine = Get-Content -LiteralPath $Corpus -TotalCount 1 -ErrorAction Stop
$m = [regex]::Match($firstLine, '"text"\s*:\s*"(.*?)",\s*"domain"')
if (-not $m.Success) {
    Write-Blocker "CORPUS_FRONT_TEXT_PARSE_FAILED"
    Write-Error "Cannot parse corpus prompts.front() text"
    exit 2
}
$promptText = [System.Text.RegularExpressions.Regex]::Unescape($m.Groups[1].Value)
if (Test-Path -LiteralPath $PromptFile) {
    $existing = [System.IO.File]::ReadAllText($PromptFile)
    if ($existing -ne $promptText) {
        Write-Blocker "PROMPT_HASH_MISMATCH corpus.front != first_corpus_prompt.txt (refuse silent overwrite of sealed official prompt)"
        Write-Error "Official K2 prompt drift — fix corpus or first_corpus_prompt.txt before seal."
        exit 6
    }
} else {
    [System.IO.File]::WriteAllText($PromptFile, $promptText)
}
[System.IO.File]::WriteAllText($PromptAlias, $promptText)
Write-Host "CORPUS_FRONT_PROMPT_CHARS=$($promptText.Length) PROMPT_FILE=$PromptFile ALIAS=$PromptAlias"

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
    "--no-display-prompt",
    "-no-cnv",
    "--load-mode", "mmap",
    "--no-repack",
    "--cpu-moe",
    "--fit", "on",
    "-ngl", "99",
    "--device", "Vulkan0,Vulkan1"
))

$TokenDumpFile = Join-Path $EvidenceDir "oracle_k2_generated_token_ids.txt"
if (Test-Path -LiteralPath $TokenDumpFile) { Remove-Item -LiteralPath $TokenDumpFile -Force }
$env:RAWRXD_ORACLE_TOKEN_DUMP = $TokenDumpFile

Write-Host "ORACLE_CMD=$Engine $($argList -join ' ')"
Write-Host "RAWRXD_ORACLE_TOKEN_DUMP=$TokenDumpFile"
$stdoutFile = Join-Path $EvidenceDir "oracle_k2_stdout.log"
$stderrFile = Join-Path $EvidenceDir "oracle_k2_stderr.log"
$proc = Start-Process -FilePath $Engine -ArgumentList $argList.ToArray() -NoNewWindow -PassThru -Wait `
    -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile
$combined = (Get-Content -LiteralPath $stdoutFile -Raw -ErrorAction SilentlyContinue) + "`n" +
            (Get-Content -LiteralPath $stderrFile -Raw -ErrorAction SilentlyContinue)
[System.IO.File]::WriteAllText($TraceFile, $combined)
Add-Content -LiteralPath $MetaFile -Value "END=$(Get-Date -Format o)`r`nORACLE_EXIT=$($proc.ExitCode)"
Write-Host "ORACLE_EXIT=$($proc.ExitCode) TRACE=$TraceFile"

$PromptCount = 0
$PredictedN = 0
$TokenIds = New-Object System.Collections.Generic.List[int]
$v = 0

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

Get-Content -LiteralPath $TraceFile -ErrorAction SilentlyContinue | ForEach-Object {
    $line = $_
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
}

Write-Host "PROMPT_N=$PromptCount PREDICTED_N=$PredictedN GENERATED_IDS=$($TokenIds.Count)"

if ($proc.ExitCode -ne 0 -and $TokenIds.Count -eq 0) {
    $tail = ""
    if (Test-Path -LiteralPath $stderrFile) {
        $tail = ((Get-Content -LiteralPath $stderrFile -Tail 40) -join " | ")
    }
    Write-Blocker "ORACLE_EXIT=$($proc.ExitCode) HOST_RAM_TOTAL_GB=$totalGB HOST_RAM_FREE_GB=$freeGB K2_FIRST_SHARD_GB=$shardGB PAGEFILE_MAX_MB=4096 STDERR_TAIL=$tail"
    Write-Error "K2 capture failed fail-closed (no invented vectors)."
    exit 10
}

if ($TokenIds.Count -eq 0) {
    Write-Blocker "NO_INTEGER_TOKEN_IDS after K2 oracle run EXIT=$($proc.ExitCode)"
    Write-Error "RECEIPT_VECTORS_VALID=0 - refuse seal (no integer token ids)."
    exit 3
}
if ($TokenIds.Count -ne $NPredict) {
    Write-Blocker "TOKEN_IDS_COUNT=$($TokenIds.Count) != N_PREDICT=$NPredict"
    Write-Error "RECEIPT_VECTORS_VALID=0 - refuse seal (count != predicted window)."
    exit 4
}
if ($PromptCount -le 0) {
    Write-Blocker "PROMPT_TOKENS_MISSING from K2 timings"
    Write-Error "RECEIPT_VECTORS_VALID=0 - refuse seal (prompt_tokens missing)."
    exit 5
}

$CsvTokens = ($TokenIds -join ",")
Write-Host "PROMPT_TOKENS=$PromptCount GENERATED_IDS=$($TokenIds.Count) - sealing K2 receipt via factory"

& $FactoryTool $Engine $Model $Corpus "$PromptCount" $CsvTokens $EngineVer $ReceiptOut
if ($LASTEXITCODE -ne 0) {
    Write-Error "FACTORY_EXIT=$LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host "REFERENCE_RECEIPT=$ReceiptOut"
Write-Host "CAPTURE=SEALED TOKEN_IDS_LEN=$($TokenIds.Count)"
Write-Host "PROMOTE=0 TIP_CLIMB=HOLD NOT_RUN!=PASS"
