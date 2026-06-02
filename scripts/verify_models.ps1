#requires -Version 5.1
param(
    [Parameter(Mandatory = $true)]
    [string]$ModelPath,
    [string]$ModelName,
    [string]$LlamaCliPath = 'D:\llama-vulkan\build\bin\llama-cli.exe',
    [string]$LlamaBenchPath = 'D:\llama-vulkan\build\bin\llama-bench.exe',
    [string]$ManifestPath = 'D:\rawrxd\scripts\model_compatibility_manifest.json',
    [switch]$AsJson
)

$ErrorActionPreference = 'Stop'

$result = [ordered]@{
    ModelName = if ([string]::IsNullOrWhiteSpace($ModelName)) { [IO.Path]::GetFileNameWithoutExtension($ModelPath) } else { $ModelName }
    ModelPath = $ModelPath
    Exists = $false
    FileSizeBytes = $null
    MinSizeBytes = $null
    ExpectedLoad = $null
    CliExitCode = $null
    Valid = $false
    Reason = ''
}

function Emit-AndExit {
    param(
        [int]$Code
    )

    if ($AsJson) {
        ($result | ConvertTo-Json -Compress) | Write-Output
    } else {
        if ($result.Valid) {
            Write-Host ("Verification Passed: {0}" -f $result.ModelPath) -ForegroundColor Green
        } else {
            Write-Host ("Verification Failed: {0}" -f $result.ModelPath) -ForegroundColor Red
            Write-Host ("Reason: {0}" -f $result.Reason)
        }
    }
    exit $Code
}

if (-not (Test-Path $ModelPath)) {
    $result.Reason = 'file not found'
    Emit-AndExit 1
}

$result.Exists = $true
$result.FileSizeBytes = (Get-Item $ModelPath).Length

if (Test-Path $ManifestPath) {
    try {
        $manifest = Get-Content $ManifestPath -Raw | ConvertFrom-Json
        $entry = $manifest.models | Where-Object {
            ($_.path -eq $ModelPath) -or ($ModelName -and ($_.name -eq $ModelName))
        } | Select-Object -First 1

        if ($entry) {
            if ($null -ne $entry.minSizeBytes) { $result.MinSizeBytes = [int64]$entry.minSizeBytes }
            if ($null -ne $entry.expectedLoad) { $result.ExpectedLoad = [bool]$entry.expectedLoad }
            if (($result.ExpectedLoad -eq $false) -and $entry.reason) {
                $result.Reason = [string]$entry.reason
            }
        }
    } catch {
        # Manifest parse errors should not hard-fail verification.
    }
}

if (($null -ne $result.MinSizeBytes) -and ($result.FileSizeBytes -lt $result.MinSizeBytes)) {
    $result.Reason = "file too small ($($result.FileSizeBytes) < $($result.MinSizeBytes))"
    Emit-AndExit 1
}

if (($null -ne $result.ExpectedLoad) -and ($result.ExpectedLoad -eq $false)) {
    if ([string]::IsNullOrWhiteSpace($result.Reason)) {
        $result.Reason = 'blocked by compatibility manifest'
    }
    Emit-AndExit 1
}

if (-not (Test-Path $LlamaCliPath)) {
    $result.Reason = "llama-cli not found: $LlamaCliPath"
    Emit-AndExit 1
}

$benchDir = Split-Path -Parent $LlamaCliPath
Push-Location $benchDir
try {
    $helpText = & $LlamaCliPath --help 2>&1 | Out-String
    $hasShowInfo = ($helpText -match '--show-info')

    if ($hasShowInfo) {
        $output = & $LlamaCliPath --show-info --model $ModelPath 2>&1 | Out-String
        $result.CliExitCode = $LASTEXITCODE
    } else {
        if (-not (Test-Path $LlamaBenchPath)) {
            $result.Reason = "llama-bench not found for fallback validation: $LlamaBenchPath"
            Emit-AndExit 1
        }

        # Minimal-load fallback for older llama-cli builds without --show-info.
        $output = & $LlamaBenchPath -v -m $ModelPath -ngl 0 -r 1 -o json -p 1 -n 1 --progress 2>&1 | Out-String
        $result.CliExitCode = $LASTEXITCODE
    }
} finally {
    Pop-Location
}

if (($result.CliExitCode -ne 0) -or ($output -match 'error loading model|failed to load model|unknown model architecture|not within the file bounds')) {
    $result.Reason = 'llama-cli header validation failed'
    Emit-AndExit 1
}

$result.Valid = $true
$result.Reason = 'ok'
Emit-AndExit 0
