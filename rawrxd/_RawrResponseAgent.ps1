# _RawrResponseAgent.ps1 — RAWRXD_RESPONSE_CODED_AGENT_001 (PowerShell proof)
#
# USER -> MODEL -> optional authorized tool -> SAME MODEL -> RESPONSE -> STOP
#
# This script is intentionally narrow:
#   - It uses the already-built rawr.exe as the inference plane.
#   - The model never supplies PowerShell. It only emits a symbolic
#     capability name (e.g. RAWR_TOOL name=git_status).
#   - PowerShell maps that capability to one of four whitelisted,
#     read-only operations. Anything else raises DENIED_TOOL.
#   - No autonomous loop, no background, no scheduler, no mutating
#     operation is exposed.
#   - The second rawr.exe invocation is logically continuous with the
#     first but does not share a KV cache; the script preserves the
#     conversation textually. Do not certify SAME_KV_SESSION=1.

$Rawr  = 'C:\Users\Garrett\rawrxd\bin\rawr.exe'
$Model = 'qwen2.5-coder:1.5b-base'   # or a GGUF path / other resolvable Ollama ref

function Invoke-RawrInference {
    param(
        [Parameter(Mandatory)][string]$Prompt,
        [int]$Tokens = 256
    )

    $result = & $Rawr run --tokens $Tokens $Model $Prompt 2>&1
    return ($result -join "`n")
}

function Invoke-AuthorizedTool {
    param([Parameter(Mandatory)][string]$Name)

    switch ($Name.Trim().ToLowerInvariant()) {
        'git_status' {
            return ((git status --short --branch 2>&1) -join "`n")
        }

        'git_log' {
            return ((git log -5 --oneline 2>&1) -join "`n")
        }

        'git_diff' {
            return ((git diff -- 2>&1) -join "`n")
        }

        'list_files' {
            return ((Get-ChildItem -Force |
                Select-Object Name,Length,LastWriteTime |
                Format-Table -AutoSize |
                Out-String).Trim())
        }

        default {
            throw "DENIED_TOOL=$Name"
        }
    }
}

function Invoke-RawrResponse {
    param([Parameter(Mandatory)][string]$UserRequest)

    $system = @'
You are RawrXD.

Respond only to the user's current request.

Understand what the user is asking before answering.
Do not invent tool results.
Do not perform additional work beyond the request.

If no external observation is necessary, output:

RAWR_RESPONSE
<your answer>

If one authorized observation is necessary, output exactly:

RAWR_TOOL
name=<tool>

Authorized tools:
git_status
git_log
git_diff
list_files

Request at most ONE tool.
Do not output shell commands.
Do not request writes or mutations.
'@

    $firstPrompt = @"
$system

USER_REQUEST:
$UserRequest
"@

    Write-Host "`n[INFERENCE 1]" -ForegroundColor Cyan
    $first = Invoke-RawrInference -Prompt $firstPrompt

    # Extract generated protocol from noisy rawr output.
    $toolMatch = [regex]::Match(
        $first,
        '(?ms)RAWR_TOOL\s*\r?\nname\s*=\s*([A-Za-z0-9_-]+)'
    )

    if (-not $toolMatch.Success) {
        $responseMatch = [regex]::Match(
            $first,
            '(?ms)RAWR_RESPONSE\s*\r?\n(.*)'
        )

        if ($responseMatch.Success) {
            return $responseMatch.Groups[1].Value.Trim()
        }

        # Keep the raw output visible if the model did not obey protocol.
        return $first.Trim()
    }

    $tool = $toolMatch.Groups[1].Value.Trim()

    Write-Host "[TOOL REQUEST] $tool" -ForegroundColor Yellow

    try {
        $observation = Invoke-AuthorizedTool -Name $tool
    }
    catch {
        $observation = "TOOL_DENIED: $($_.Exception.Message)"
    }

    Write-Host "[OBSERVATION]" -ForegroundColor Yellow
    Write-Host $observation

    # Preserve turn 1 explicitly because rawr run itself is currently
    # one-shot rather than a persistent chat session.
    $secondPrompt = @"
$system

USER_REQUEST:
$UserRequest

YOUR_PREVIOUS_OUTPUT:
$first

RAWR_OBSERVATION
tool=$tool
output:
$observation

You now have the real observation.

Answer the original user request using it.
Do not request another tool.

Output exactly:

RAWR_RESPONSE
<final answer>
"@

    Write-Host "`n[INFERENCE 2]" -ForegroundColor Cyan
    $second = Invoke-RawrInference -Prompt $secondPrompt

    $responseMatch = [regex]::Match(
        $second,
        '(?ms)RAWR_RESPONSE\s*\r?\n(.*)'
    )

    if ($responseMatch.Success) {
        return $responseMatch.Groups[1].Value.Trim()
    }

    return $second.Trim()
}
