# sessionStart — MOTD_ACK=0; never silent-empty
$ErrorActionPreference = 'Continue'
try {
    . (Join-Path $PSScriptRoot 'motd-common.ps1')
    $in = Get-HookInput
    $cid = ''
    if ($null -ne $in -and $null -ne $in.conversation_id) { $cid = [string]$in.conversation_id }
    Set-MotdState -conversationId $cid -acked $false -continueEnsure $false
    Write-HookJson @{
        continue = $true
        additional_context = 'MOTD_ACK=0 CURSOR_AGENTIC_PRIMARY=1 Prefer Cursor Task for autonomous workers; PROMOTE=0 TIP_CLIMB=HOLD.'
    }
    exit 0
}
catch {
    Write-Output '{"continue":true}'
    exit 0
}
