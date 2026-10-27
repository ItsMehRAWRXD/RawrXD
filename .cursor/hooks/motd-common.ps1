# Shared MOTD + continue-ensure helpers (PassiveRoleNotRoleplay)
$script:MotdNeedle = 'PassiveRoleNotRoleplay'
$script:StateDir = Join-Path $PSScriptRoot 'state'
$script:StateFile = Join-Path $script:StateDir 'motd-ack.json'
$script:ShortTrigger = 'Please continue ensuring'
$script:MaxTrigger = 'Please continue ensuring that the streamer is complete and can run agentic'

function Get-HookInput {
    # Avoid [Console]::In.ReadToEnd() hang when Cursor leaves stdin open.
    try {
        $stdin = [Console]::OpenStandardInput()
        $buf = New-Object byte[] 1048576
        $readTask = $stdin.ReadAsync($buf, 0, $buf.Length)
        if (-not $readTask.Wait(500)) {
            return $null
        }
        $n = $readTask.Result
        if ($n -le 0) { return $null }
        $ms = New-Object System.IO.MemoryStream
        $ms.Write($buf, 0, $n)
        # Drain briefly if more bytes arrive
        $deadline = [DateTime]::UtcNow.AddMilliseconds(300)
        while ([DateTime]::UtcNow -lt $deadline) {
            $more = $stdin.ReadAsync($buf, 0, $buf.Length)
            if (-not $more.Wait(50)) { break }
            $k = $more.Result
            if ($k -le 0) { break }
            $ms.Write($buf, 0, $k)
        }
        $raw = [Text.Encoding]::UTF8.GetString($ms.ToArray())
        if ([string]::IsNullOrWhiteSpace($raw)) { return $null }
        try { return $raw | ConvertFrom-Json } catch { return $null }
    } catch {
        return $null
    }
}

function Write-HookJson([hashtable]$obj) {
    # Prefer Write-Output so Cursor's redirected stdout always sees the JSON
    # ([Console]::Out can miss the pipe under failClosed preToolUse).
    try {
        $json = ($obj | ConvertTo-Json -Compress -Depth 8)
        if ([string]::IsNullOrWhiteSpace($json)) {
            Write-Output '{"permission":"allow","note":"empty_json"}'
            return
        }
        Write-Output $json
    } catch {
        Write-Output '{"permission":"allow","note":"write_hook_json_catch"}'
    }
}

function Ensure-MotdStateDir {
    if (-not (Test-Path -LiteralPath $script:StateDir)) {
        New-Item -ItemType Directory -Path $script:StateDir -Force | Out-Null
    }
}

function Get-MotdState {
    Ensure-MotdStateDir
    if (-not (Test-Path -LiteralPath $script:StateFile)) {
        return @{ acked = $false; conversation_id = ''; continue_ensure = $false }
    }
    try {
        $o = Get-Content -LiteralPath $script:StateFile -Raw -ErrorAction Stop | ConvertFrom-Json
        return @{
            acked = [bool]$o.acked
            conversation_id = [string]$o.conversation_id
            continue_ensure = [bool]$o.continue_ensure
        }
    } catch {
        return @{ acked = $false; conversation_id = ''; continue_ensure = $false }
    }
}

function Set-MotdState([string]$conversationId, [bool]$acked, [bool]$continueEnsure = $false) {
    Ensure-MotdStateDir
    $payload = @{
        conversation_id = $conversationId
        acked = $acked
        continue_ensure = $continueEnsure
        updated = (Get-Date).ToString('o')
    }
    ($payload | ConvertTo-Json -Compress) | Set-Content -LiteralPath $script:StateFile -Encoding utf8
}

function Test-IsMotdPath([string]$path) {
    if ([string]::IsNullOrWhiteSpace($path)) { return $false }
    $n = $path.Replace('\', '/')
    return ($n -match 'PassiveRoleNotRoleplay\.mdc?$') -or ($n -match [regex]::Escape($script:MotdNeedle))
}

function Test-IsMotdReadTool($inputObj) {
    $name = [string]$inputObj.tool_name
    if ($name -ne 'Read' -and $name -ne 'read_file' -and $name -ne 'read_motd') { return $false }
    if ($name -eq 'read_motd') { return $true }
    $ti = $inputObj.tool_input
    if ($null -eq $ti) { return $false }
    $path = ''
    if ($null -ne $ti.path) { $path = [string]$ti.path }
    elseif ($null -ne $ti.file_path) { $path = [string]$ti.file_path }
    elseif ($null -ne $ti.target_file) { $path = [string]$ti.target_file }
    return (Test-IsMotdPath $path)
}

function Test-ContinueEnsurePrompt([string]$text) {
    if ([string]::IsNullOrWhiteSpace($text)) { return $false }
    if ($text.Contains($script:MaxTrigger)) { return $true }
    return $text.Contains($script:ShortTrigger)
}

function Get-ContinueEnsureContext {
    return @(
        'CONTINUE_ENSURE_MATCH=1',
        'PARENT_MODE=PASSIVE_COORDINATOR',
        'WORKER_COUNT=1 PARENT_EXECUTES_DELEGATED_WORK=0 PROMOTE=0 TIP_CLIMB=HOLD',
        'Read MOTD then StreamerAgenticContinueEnsure.mdc + MultitaskMode.mdc.',
        'Emit 3-line ack + CONTINUE_ENSURE=DISPATCHED; launch exactly one background Task (run_in_background=true); end parent turn.',
        'Worker: live E2E only. SOURCE_WIRED!=RUNTIME_REACHED!=TOKEN_SURVIVED!=PERFORMANCE_PASS. PROMOTE=0. No invented PASS.',
        'CURSOR_AGENTIC_PRIMARY=1'
    ) -join ' '
}
