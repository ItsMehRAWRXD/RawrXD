param(
    [string]$Model = 'nemotron-3.5-lightning:30b',
    [string]$OutputDirectory = 'evidence/nemotron-mtp-recovery'
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null
function Capture([string]$Name, [scriptblock]$Action) {
    try {
        $value = & $Action
        [pscustomobject]@{ status = 'ok'; value = $value }
    } catch {
        [pscustomobject]@{ status = 'unavailable'; error = $_.Exception.Message }
    }
}
$manifest = [ordered]@{
    schema_version = 1
    collected_at_utc = (Get-Date).ToUniversalTime().ToString('o')
    model_requested = $Model
    host = [ordered]@{
        os = [System.Environment]::OSVersion.VersionString
        powershell = $PSVersionTable.PSVersion.ToString()
    }
    ollama_version = Capture 'ollama_version' { (& ollama --version 2>&1 | Out-String).Trim() }
    ollama_show = Capture 'ollama_show' { (& ollama show $Model --modelfile 2>&1 | Out-String).Trim() }
    ollama_list = Capture 'ollama_list' { (& ollama list 2>&1 | Out-String).Trim() }
    ollama_ps = Capture 'ollama_ps' { (& ollama ps 2>&1 | Out-String).Trim() }
    runtime_processes = Capture 'runtime_processes' {
        @(Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^(ollama|llama-server|llama-cli)(\\.exe)?$' } |
          Select-Object Name,ProcessId,ExecutablePath)
    }
    executable_hashes = Capture 'executable_hashes' {
        @(Get-CimInstance Win32_Process | Where-Object { $_.Name -match '^(ollama|llama-server|llama-cli)(\\.exe)?$' } |
          Where-Object { $_.ExecutablePath -and (Test-Path -LiteralPath $_.ExecutablePath) } |
          Select-Object -ExpandProperty ExecutablePath -Unique |
          ForEach-Object { [pscustomobject]@{ path = $_; sha256 = (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash } })
    }
    benchmark_command = $null
    exact_model_blob_sha256 = $null
    prompt_sha256 = $null
    mtp_enabled_result = $null
    mtp_disabled_result = $null
    verdict = 'BLOCKED_PENDING_EXACT_COMMAND_AND_ARTIFACT'
}
$target = Join-Path $OutputDirectory 'local_recovery.json'
$manifest | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $target -Encoding UTF8
Write-Host "Local evidence written to $target"
Write-Host 'Review for private paths before sharing. No benchmark executed; no PASS claimed.'
