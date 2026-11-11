# preToolUse — deny until MOTD Read; fail-closed on policy, never silent-empty
$ErrorActionPreference = 'Continue'
# Emit ASAP if anything below hangs — Cursor failClosed treats empty stdout as block.
function Emit-Allow([string]$note = '') {
    if ($note) {
        Write-Output ("{`"permission`":`"allow`",`"note`":`"$note`"}")
    } else {
        Write-Output '{"permission":"allow"}'
    }
}
function Emit-Deny([string]$msg) {
    $safe = ($msg -replace '\\', '\\' -replace '"', '\"')
    if ($safe.Length -gt 180) { $safe = $safe.Substring(0, 180) }
    Write-Output ("{`"permission`":`"deny`",`"agent_message`":`"$safe`",`"user_message`":`"Blocked: must read PassiveRoleNotRoleplay MOTD before any other tool.`"}")
}

try {
    $stateFile = Join-Path $PSScriptRoot 'state\motd-ack.json'
    # Fast path: if already acked this turn, allow without stdin (avoids Cancel/hang).
    if (Test-Path -LiteralPath $stateFile) {
        $rawSt = Get-Content -LiteralPath $stateFile -Raw -ErrorAction SilentlyContinue
        if ($rawSt -and $rawSt -match '"acked"\s*:\s*true') {
            Emit-Allow 'acked_fast'
            exit 0
        }
    }

    . (Join-Path $PSScriptRoot 'motd-common.ps1')
    $in = Get-HookInput
    if ($null -eq $in) {
        Emit-Allow 'empty_hook_input'
        exit 0
    }

    $cid = ''
    if ($null -ne $in.conversation_id) { $cid = [string]$in.conversation_id }
    $st = Get-MotdState

    if ($cid -and $st.conversation_id -and ($cid -ne $st.conversation_id)) {
        Set-MotdState -conversationId $cid -acked $false -continueEnsure $false
        $st = Get-MotdState
    }

    if ($st.acked) {
        Emit-Allow
        exit 0
    }

    if (Test-IsMotdReadTool $in) {
        Set-MotdState -conversationId $cid -acked $true -continueEnsure ([bool]$st.continue_ensure)
        Emit-Allow 'motd_optimistic_ack'
        exit 0
    }

    Emit-Deny 'MOTD gate: Read .cursor/rules/PassiveRoleNotRoleplay.mdc before any other tool.'
    exit 0
}
catch {
    $msg = $_.Exception.Message
    if ($msg.Length -gt 200) { $msg = $msg.Substring(0, 200) }
    Write-Output ('{"permission":"deny","agent_message":"MOTD hook error: ' + ($msg -replace '\\','\\\\' -replace '"','\"') + '","user_message":"MOTD pre-tool hook error (non-empty deny)."}')
    exit 0
}
