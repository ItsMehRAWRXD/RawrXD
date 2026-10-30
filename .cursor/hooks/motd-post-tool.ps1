# postToolUse — MOTD_ACK=1 after PassiveRoleNotRoleplay Read; never silent-empty
$ErrorActionPreference = 'Continue'
try {
    . (Join-Path $PSScriptRoot 'motd-common.ps1')
    $in = Get-HookInput
    if ($null -eq $in) {
        Write-HookJson @{}
        exit 0
    }

    if (Test-IsMotdReadTool $in) {
        $cid = ''
        if ($null -ne $in.conversation_id) { $cid = [string]$in.conversation_id }
        $st = Get-MotdState
        Set-MotdState -conversationId $cid -acked $true -continueEnsure ([bool]$st.continue_ensure)
        $ctx = 'MOTD_ACK=1 TOOLS_UNLOCKED=1 for this user-message turn. CURSOR_AGENTIC_PRIMARY=1'
        if ($st.continue_ensure) {
            $ctx = $ctx + ' ' + (Get-ContinueEnsureContext)
        }
        Write-HookJson @{ additional_context = $ctx }
        exit 0
    }

    Write-HookJson @{}
    exit 0
}
catch {
    Write-Output '{"additional_context":"MOTD post-tool hook error; optimistic ACK may already be set by pre-tool."}'
    exit 0
}
