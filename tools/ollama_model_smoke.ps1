[CmdletBinding()]
param(
    [string]$BaseUrl = 'http://127.0.0.1:11434',
    [int]$TimeoutSeconds = 120,
    [switch]$RestartOnFailure,
    [string[]]$ModelName
)

$ErrorActionPreference = 'Continue'
$ollamaExe = 'C:\Users\Garrett\AppData\Local\Programs\Ollama\ollama.exe'

function Test-Ollama {
    try {
        $probe = Invoke-WebRequest -Uri "$BaseUrl/api/tags" -TimeoutSec 3
        return ($probe.StatusCode -eq 200)
    } catch {
        return $false
    }
}

function Ensure-Ollama {
    if (Test-Ollama) { return $true }
    if (-not $RestartOnFailure) { return $false }
    if (-not (Test-Path -LiteralPath $ollamaExe)) { return $false }
    Start-Process -FilePath $ollamaExe -ArgumentList 'serve' -WindowStyle Hidden
    for ($attempt = 0; $attempt -lt 45; $attempt++) {
        Start-Sleep -Seconds 1
        if (Test-Ollama) { return $true }
    }
    return $false
}

function Get-ModelSpec([string]$Name) {
    try {
        return Invoke-RestMethod -Uri "$BaseUrl/api/show" -Method Post -ContentType 'application/json' `
            -Body (@{ model = $Name } | ConvertTo-Json -Compress) -TimeoutSec 15
    } catch {
        return $null
    }
}

function Get-ThinkWireValue($Spec) {
    $capabilities = @($Spec.capabilities | ForEach-Object { [string]$_ })
    $values = @()
    if ($null -ne $Spec.thinking -and $null -ne $Spec.thinking.values) {
        $values = @($Spec.thinking.values)
    }
    $hasCompletion = $capabilities -contains 'completion'
    $isEmbeddingOnly = ($capabilities -contains 'embedding') -and -not $hasCompletion
    $boolValues = @($values | Where-Object { $_ -is [bool] })
    $stringValues = @($values | Where-Object { $_ -is [string] } | ForEach-Object { [string]$_ })
    $levels = @('low', 'medium', 'high') | Where-Object { $stringValues -contains $_ }

    if ($isEmbeddingOnly) {
        return [pscustomobject]@{ completion = $false; embeddingOnly = $true; value = $false; reserve = 0; wire = 'bool' }
    }
    if ($levels.Count -gt 0) {
        # The lowest named level is enough to prove a final response without
        # consuming the entire tiny smoke budget in hidden reasoning.
        return [pscustomobject]@{ completion = $true; embeddingOnly = $false; value = $levels[0]; reserve = 512; wire = 'level' }
    }
    if ($boolValues -contains $false) {
        return [pscustomobject]@{ completion = $true; embeddingOnly = $false; value = $false; reserve = 0; wire = 'bool' }
    }
    if ($boolValues -contains $true -or $capabilities -contains 'thinking') {
        return [pscustomobject]@{ completion = $true; embeddingOnly = $false; value = $true; reserve = 512; wire = 'bool' }
    }
    return [pscustomobject]@{ completion = $hasCompletion -or $capabilities.Count -eq 0; embeddingOnly = $false; value = $false; reserve = 0; wire = 'bool' }
}

if (-not (Ensure-Ollama)) {
    throw "Ollama is not reachable at $BaseUrl"
}

$inventory = @((Invoke-RestMethod -Uri "$BaseUrl/api/tags" -TimeoutSec 15).models)
$localModels = @($inventory | Where-Object {
    $name = [string]$_.name
    $name -notmatch '(:cloud$|-cloud$)' -and
        ($ModelName.Count -eq 0 -or $ModelName -contains $name)
})

$cloudSkipped = @($inventory | Where-Object { ([string]$_.name) -match '(:cloud$|-cloud$)' }).Count

Write-Output "LOCAL_MODEL_COUNT=$($localModels.Count) CLOUD_SKIPPED=$cloudSkipped"
$results = @()
$index = 0

foreach ($model in $localModels) {
    $index++
    $name = [string]$model.name
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $status = 'FAIL'
    $detail = ''
    $sample = ''
    $recovered = $false
    $spec = Get-ModelSpec $name
    $wire = if ($spec) { Get-ThinkWireValue $spec } else { $null }

    if (-not $spec) {
        $status = 'MODEL_METADATA_UNAVAILABLE'
        $detail = 'api/show failed; model is not admitted as a runnable text route'
        $watch.Stop()
        $results += [pscustomobject]@{ model = $name; status = $status; ms = $watch.ElapsedMilliseconds; detail = $detail; sample = $sample; recovered = $recovered }
        Write-Output "[$index/$($localModels.Count)] $name | $status"
        continue
    }
    if ($wire.embeddingOnly) {
        $status = 'UNSUPPORTED_COMPLETION'
        $detail = 'embedding/vision route; excluded from text-chat smoke'
        $watch.Stop()
        $results += [pscustomobject]@{ model = $name; status = $status; ms = $watch.ElapsedMilliseconds; detail = $detail; sample = $sample; recovered = $recovered }
        Write-Output "[$index/$($localModels.Count)] $name | $status"
        continue
    }

    if (-not (Ensure-Ollama)) {
        $status = 'OLLAMA_UNAVAILABLE'
        $detail = 'service did not recover before request'
        $watch.Stop()
        $results += [pscustomobject]@{ model = $name; status = $status; ms = $watch.ElapsedMilliseconds; detail = $detail; sample = $sample; recovered = $recovered }
        Write-Output "[$index/$($localModels.Count)] $name | $status"
        continue
    }

    $request = @{
        model = $name
        prompt = 'Reply with exactly RAWRXD_MODEL_SMOKE'
        stream = $false
        think = $wire.value
        keep_alive = '0'
        options = @{ num_predict = 16 + $wire.reserve; temperature = 0 }
    } | ConvertTo-Json -Depth 5 -Compress

    try {
        $reply = Invoke-WebRequest -Uri "$BaseUrl/api/generate" -Method Post -ContentType 'application/json' -Body $request -TimeoutSec $TimeoutSeconds
        $payload = $reply.Content | ConvertFrom-Json
        if ($payload.error) {
            $detail = [string]$payload.error
        } elseif (-not [string]::IsNullOrWhiteSpace([string]$payload.response)) {
            $status = 'PASS'
            $sample = ([string]$payload.response).Replace("`r", ' ').Replace("`n", ' ').Trim()
        } elseif (-not [string]::IsNullOrWhiteSpace([string]$payload.thinking)) {
            $status = 'EMPTY_RESPONSE_THINKING'
            $detail = 'final response empty while thinking was returned'
        } else {
            $detail = 'empty response'
        }
    } catch {
        $detail = $_.Exception.Message
        if (-not (Test-Ollama)) {
            $status = 'BACKEND_CRASH_OR_STOP'
            $recovered = Ensure-Ollama
        } elseif ($detail -match 'timed out|timeout') {
            $status = 'TIMEOUT'
        }
        if ($detail.Length -gt 160) { $detail = $detail.Substring(0, 160) }
    }

    $watch.Stop()
    $results += [pscustomobject]@{ model = $name; status = $status; ms = $watch.ElapsedMilliseconds; detail = $detail; sample = $sample; recovered = $recovered }
    $summary = if ($detail) { $detail } else { $sample }
    Write-Output "[$index/$($localModels.Count)] $name | $status | $($watch.ElapsedMilliseconds)ms | $summary"
}

$passCount = @($results | Where-Object status -eq 'PASS').Count
Write-Output "OLLAMA_LOCAL_MODEL_SMOKE_TOTAL=$($results.Count) PASS=$passCount NONPASS=$($results.Count - $passCount)"
$results | Where-Object status -ne 'PASS' | Format-Table model,status,ms,detail -AutoSize
