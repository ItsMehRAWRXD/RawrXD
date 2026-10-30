# beforeSubmitPrompt — MOTD_ACK=0 every turn; never silent-empty
$ErrorActionPreference = 'Continue'
try {
    . (Join-Path $PSScriptRoot 'motd-common.ps1')
    $in = Get-HookInput
    $cid = ''
    $prompt = ''
    if ($null -ne $in) {
        if ($null -ne $in.conversation_id) { $cid = [string]$in.conversation_id }
        if ($null -ne $in.prompt) { $prompt = [string]$in.prompt }
        elseif ($null -ne $in.text) { $prompt = [string]$in.text }
        elseif ($null -ne $in.content) { $prompt = [string]$in.content }
    }
    $ce = Test-ContinueEnsurePrompt $prompt
    Set-MotdState -conversationId $cid -acked $false -continueEnsure $ce
    $motdCtx = @(
        'MOTD_ACK=0 for this user message.',
        'Before any other tool: Read g:\~dev\.cursor\rules\PassiveRoleNotRoleplay.mdc',
        '(or rawrxd\.cursor\rules\PassiveRoleNotRoleplay.md / .mdc).',
        'preToolUse denies non-MOTD tools until that Read succeeds (MOTD_ACK=1).',
        'CURSOR_AGENTIC_PRIMARY=1 Autonomous workers: Cursor Task (run_in_background) first; do not invent parallel non-Cursor orchestrators for the same job.'
    ) -join ' '
    $out = @{
        continue = $true
        additional_context = $motdCtx
    }
    if ($ce) {
        $out['additional_context'] = $motdCtx + ' ' + (Get-ContinueEnsureContext)
    }
    Write-HookJson $out
    exit 0
}
catch {
    Write-Output '{"continue":true,"additional_context":"MOTD before-submit hook error; still require PassiveRoleNotRoleplay Read."}'
    exit 0
}
