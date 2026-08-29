<#
.SYNOPSIS
  AGENT-FIRST-TOKEN-001 - certify render -> tokenize -> prefill -> first decode token.
#>
param(
    [string]$Model = "F:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf",
    [string]$AgentExe = "F:\~dev\rawrxd\build-ninja\bin\RawrXD-Agentic.exe",
    [string]$EvidenceRoot = "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\AGENT_FIRST_TOKEN_001",
    [string]$Workspace = "F:\~dev\rawrxd\evidence\AGENT_E2E_002b\work_first_token",
    [int]$TimeoutMs = 600000
)

$ErrorActionPreference = "Continue"
if (-not (Test-Path -LiteralPath $AgentExe)) { throw "missing $AgentExe - rebuild RawrXD-Agentic" }
if (-not (Test-Path -LiteralPath $Model)) { throw "missing $Model" }

New-Item -ItemType Directory -Force -Path $EvidenceRoot | Out-Null
if (Test-Path -LiteralPath $Workspace) { Remove-Item -LiteralPath $Workspace -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Workspace | Out-Null
Set-Content -LiteralPath (Join-Path $Workspace "hello.txt") -Value "probe" -Encoding ascii

$task = "Reply with the single word OK. No tools."

function Invoke-FirstTokenStick {
    param(
        [Parameter(Mandatory)][string]$Label,
        [Parameter(Mandatory)][string]$ChatFamily
    )

    $stickDir = Join-Path $EvidenceRoot $Label
    if (Test-Path -LiteralPath $stickDir) { Remove-Item -LiteralPath $stickDir -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $stickDir | Out-Null

    Get-ChildItem Env:RAWRXD_* -ErrorAction SilentlyContinue | ForEach-Object { Remove-Item "Env:$($_.Name)" }
    $env:RAWRXD_GREEDY = "1"
    $env:RAWRXD_AGENT_FIRST_TOKEN = "1"
    if ($ChatFamily -ne "auto") { $env:RAWRXD_CHAT_FAMILY = $ChatFamily }

    $console = Join-Path $stickDir "agent.console.txt"
    Write-Host ("AGENT_BEGIN={0} stick={1} family={2}" -f (Get-Date -Format o), $Label, $ChatFamily)
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $argLine = "--model `"$Model`" --workspace `"$Workspace`" --max-steps 1 --max-tokens 1 --no-stream --task `"$task`""
    cmd /c "`"$AgentExe`" $argLine > `"$console`" 2>&1"
    $exitCode = $LASTEXITCODE
    $sw.Stop()
    Write-Host ("AGENT_END={0} EXIT={1} ELAPSED_MS={2}" -f (Get-Date -Format o), $exitCode, $sw.ElapsedMilliseconds)

    foreach ($name in @("rendered_prompt.txt","rendered_prompt.bin","deep2_ids.txt","first_token.txt")) {
        $src = Join-Path $EvidenceRoot $name
        if (Test-Path -LiteralPath $src) {
            Copy-Item -LiteralPath $src -Destination (Join-Path $stickDir $name) -Force
        }
    }

    $markers = @{
        MODEL_READY = $false
        PROMPT_RENDERED = $false
        TOKENIZED = $false
        PREFILL_BEGIN = $false
        PREFILL_DONE = $false
        DECODE_BEGIN = $false
        TOKEN = $false
        first_token_id = -1
        token_count = -1
        rendered_bytes = -1
        chat_family = $ChatFamily
    }

    if (Test-Path -LiteralPath $console) {
        $text = Get-Content -LiteralPath $console -Raw -ErrorAction SilentlyContinue
        if ($text -match '\[AGENT\] MODEL_READY chat_family=(\S+)') { $markers.MODEL_READY = $true; $markers.chat_family = $Matches[1] }
        if ($text -match '\[AGENT\] PROMPT_RENDERED bytes=(\d+)') { $markers.PROMPT_RENDERED = $true; $markers.rendered_bytes = [int]$Matches[1] }
        if ($text -match '\[AGENT\] TOKENIZED count=(\d+)') { $markers.TOKENIZED = $true; $markers.token_count = [int]$Matches[1] }
        if ($text -match '\[AGENT\] PREFILL_BEGIN') { $markers.PREFILL_BEGIN = $true }
        if ($text -match '\[AGENT\] PREFILL_DONE') { $markers.PREFILL_DONE = $true }
        if ($text -match '\[AGENT\] DECODE_BEGIN') { $markers.DECODE_BEGIN = $true }
        if ($text -match '\[AGENT\] TOKEN id=(-?\d+)') { $markers.TOKEN = $true; $markers.first_token_id = [int]$Matches[1] }
        if ($text -match '\[AGENT\] FIRST_TOKEN id=(-?\d+)') { $markers.TOKEN = $true; $markers.first_token_id = [int]$Matches[1] }
    }

    $pass = [bool]($markers.MODEL_READY -and $markers.PROMPT_RENDERED -and $markers.TOKENIZED -and
                   $markers.PREFILL_BEGIN -and $markers.PREFILL_DONE -and $markers.DECODE_BEGIN -and
                   $markers.TOKEN -and ($markers.first_token_id -ge 0))

    $root = "UNKNOWN"
    if (-not $markers.MODEL_READY) { $root = "MODEL_LOAD" }
    elseif (-not $markers.PROMPT_RENDERED) { $root = "CHAT_TEMPLATE" }
    elseif (-not $markers.TOKENIZED -or $markers.token_count -le 0) { $root = "TOKENIZER" }
    elseif (-not $markers.PREFILL_DONE) { $root = "PREFILL" }
    elseif (-not $markers.TOKEN) { $root = "DECODE" }
    else { $root = "NONE" }

    $summary = @"
# AGENT-FIRST-TOKEN-001 / $Label

model_loaded=$($markers.MODEL_READY)
chat_family=$($markers.chat_family)
rendered_prompt_bytes=$($markers.rendered_bytes)
token_count=$($markers.token_count)

prefill_enter=$($markers.PREFILL_BEGIN)
prefill_exit=$($markers.PREFILL_DONE)

decode_0_enter=$($markers.DECODE_BEGIN)
decode_0_token=$($markers.first_token_id)

agent_exit=$exitCode
elapsed_ms=$($sw.ElapsedMilliseconds)
RESULT=$(if ($pass) { 'PASS' } else { 'FAIL' })
ROOT_DOMAIN=$root
"@
    Set-Content -LiteralPath (Join-Path $stickDir "RUN_SUMMARY.txt") -Value $summary -Encoding utf8
    Write-Host $summary
    return [pscustomobject]@{
        Label = $Label
        Pass = $pass
        Root = $root
        FirstToken = $markers.first_token_id
        TokenCount = $markers.token_count
        Family = $markers.chat_family
        Exit = $exitCode
        ElapsedMs = $sw.ElapsedMilliseconds
    }
}

$a = Invoke-FirstTokenStick -Label "A_auto" -ChatFamily "auto"
$b = Invoke-FirstTokenStick -Label "B_chatml" -ChatFamily "chatml"

$overall = "FAIL"
if ($a.Pass -and $b.Pass) { $overall = "PASS" }
elseif ($a.Pass -or $b.Pass) { $overall = "PARTIAL" }

$verdict = @"
# AGENT-FIRST-TOKEN-001 VERDICT

overall=$overall
stick_A_auto=$($a.Pass) family=$($a.Family) token=$($a.FirstToken) n=$($a.TokenCount) root=$($a.Root) ms=$($a.ElapsedMs)
stick_B_chatml=$($b.Pass) family=$($b.Family) token=$($b.FirstToken) n=$($b.TokenCount) root=$($b.Root) ms=$($b.ElapsedMs)

decision_tree:
  A fail B pass  -> chat_template frontend (phi3 auto suspect)
  A pass B fail  -> forced ChatML wrong for TinyLlama
  both fail at TOKENIZER -> tokenizer
  both fail at PREFILL -> Deep2 prefill
  both fail at DECODE -> Deep2 decode
  both pass first token -> advance to tool-call / 002b
"@
Set-Content -LiteralPath (Join-Path $EvidenceRoot "VERDICT.md") -Value $verdict -Encoding utf8
Get-Content (Join-Path $EvidenceRoot "VERDICT.md")
if (-not ($a.Pass -or $b.Pass)) { exit 2 }
exit 0
