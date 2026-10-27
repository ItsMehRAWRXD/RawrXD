# preToolUse — deny until MOTD Read; ALWAYS emit JSON (failClosed + empty = hard block)
$ErrorActionPreference = 'Continue'
[Console]::Out.Flush()
try {
    . (Join-Path $PSScriptRoot 'motd-common.ps1')
    $in = Get-HookInput
    if ($null -eq $in) {
        Write-HookJson @{ permission = 'allow'; note = 'empty_or_timeout_hook_input' }
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
        Write-HookJson @{ permission = 'allow' }
        exit 0
    }

    if (Test-IsMotdReadTool $in) {
        Set-MotdState -conversationId $cid -acked $true -continueEnsure ([bool]$st.continue_ensure)
        Write-HookJson @{ permission = 'allow'; motd_optimistic_ack = $true }
        exit 0
    }

    Write-HookJson @{
        permission = 'deny'
        agent_message = 'MOTD gate: Read g:\~dev\.cursor\rules\PassiveRoleNotRoleplay.mdc before any other tool.'
        user_message = 'Blocked: must read PassiveRoleNotRoleplay MOTD before any other tool.'
    }
    exit 0
}
catch {
    [Console]::Out.WriteLine('{"permission":"allow","note":"motd_pre_tool_catch_allow_to_unblock_agentic"}')
    exit 0
}
