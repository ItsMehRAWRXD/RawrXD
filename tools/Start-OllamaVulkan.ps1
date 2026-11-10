[CmdletBinding()]
param(
    [string]$OllamaExe = 'C:\Users\Garrett\AppData\Local\Programs\Ollama\ollama.exe',
    [string]$Models = 'F:\OllamaModels',
    [int]$Port = 11434
)

$ErrorActionPreference = 'Stop'
$logRoot = if ($env:RAWRXD_LOG_DIR) { $env:RAWRXD_LOG_DIR } else { (Get-Location).Path }
$runtimeLog = Join-Path $logRoot 'ollama_runtime.log'
function Write-RawrxdRuntime([string]$Line) {
    try { Add-Content -LiteralPath $runtimeLog -Value $Line -Encoding UTF8 } catch { }
}
if (-not (Test-Path -LiteralPath $OllamaExe)) {
    throw "Ollama executable not found: $OllamaExe"
}
if (-not (Test-Path -LiteralPath $Models)) {
    throw "Ollama model directory not found: $Models"
}

# ROCm is intentionally excluded for this Windows GPU configuration. The
# installed ROCm runner reaches gfx1201 but fails in rocblaslt/Tensile with
# 'no kernel image is available'; Vulkan is the verified AMD path.
[Environment]::SetEnvironmentVariable('OLLAMA_VULKAN', '1', 'User')
[Environment]::SetEnvironmentVariable('OLLAMA_LLM_LIBRARY', 'vulkan', 'User')
[Environment]::SetEnvironmentVariable('OLLAMA_MODELS', $Models, 'User')

$env:OLLAMA_VULKAN = '1'
$env:OLLAMA_LLM_LIBRARY = 'vulkan'
$env:OLLAMA_MODELS = $Models
$env:OLLAMA_HOST = "127.0.0.1:$Port"
$env:OLLAMA_DEBUG = 'INFO'

$existing = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($existing) {
    $ownerIds = $existing | Select-Object -ExpandProperty OwningProcess -Unique
    foreach ($ownerId in $ownerIds) {
        $owner = Get-CimInstance Win32_Process -Filter "ProcessId=$ownerId"
        if ($owner.Name -eq 'ollama.exe' -and $owner.ExecutablePath -eq $OllamaExe) {
            Stop-Process -Id $ownerId -Force
        } else {
            Write-RawrxdRuntime "OLLAMA_PORT_REFUSAL=PASS PORT=$Port PID=$ownerId"
            throw "Port $Port is occupied by a non-Ollama process (PID $ownerId)."
        }
    }
}

Write-Host "Starting Ollama with Vulkan backend on $($env:OLLAMA_HOST)..."
Write-Host "OLLAMA_LLM_LIBRARY=$env:OLLAMA_LLM_LIBRARY"
Write-Host "OLLAMA_VULKAN=$env:OLLAMA_VULKAN"
Write-RawrxdRuntime "OLLAMA_LAUNCH=PASS OLLAMA_LLM_LIBRARY=vulkan OLLAMA_VULKAN=1 PORT=$Port"
& $OllamaExe serve
