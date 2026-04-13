param(
    [string]$ImagePath = "C:\Users\HiH8e\OneDrive\Desktop\Screenshot 2026-04-12 142141.png",
    [string]$BaseUrl = "http://localhost:11434",
    [string]$VisionModel = "qwen3-vl:4b",
    [string[]]$NonVisionModels = @("phi:latest", "phi3:mini"),
    [string]$ReportPath = "D:\RawrXD\reports\14day\vision_hotpatch_smoke.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Net.Http

function Invoke-OllamaChatJson {
    param([string]$Url, [string]$Body)

    $handler = New-Object System.Net.Http.HttpClientHandler
    $client = New-Object System.Net.Http.HttpClient($handler)
    $client.Timeout = [TimeSpan]::FromSeconds(600)
    try {
        $content = New-Object System.Net.Http.StringContent($Body, [System.Text.Encoding]::UTF8, "application/json")
        $response = $client.PostAsync($Url, $content).GetAwaiter().GetResult()
        $respBody = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        return [ordered]@{
            statusCode = [int]$response.StatusCode
            isSuccess = $response.IsSuccessStatusCode
            body = $respBody
        }
    } finally {
        $client.Dispose()
        $handler.Dispose()
    }
}

function Test-ModelPresent {
    param([string]$ModelName)
    $output = & ollama list
    return ($output | Select-String -SimpleMatch $ModelName -Quiet)
}

if (-not (Test-Path $ImagePath)) {
    throw "Image not found: $ImagePath"
}

$reportDir = Split-Path -Parent $ReportPath
if (-not (Test-Path $reportDir)) {
    New-Item -ItemType Directory -Path $reportDir -Force | Out-Null
}

$imageBytes = [System.IO.File]::ReadAllBytes($ImagePath)
$imageBase64 = [Convert]::ToBase64String($imageBytes)

$prompt = "Describe the screenshot in 5 concise bullets. If you cannot see images, explicitly say so."
$chatUrl = "$BaseUrl/api/chat"

$result = [ordered]@{
    ok = $true
    timestamp = (Get-Date).ToUniversalTime().ToString("o")
    imagePath = $ImagePath
    rawrxdClientSupportsImageUpload = $false
    rawrxdClientReason = "src/ollama_client.h and src/ollama_client.cpp define no image field on OllamaChatMessage and createChatRequestJson serializes only role/content/tool fields."
    hotpatchVisionForNonVisionModelsObserved = $false
    tests = @()
}

if (Test-ModelPresent $VisionModel) {
    $visionBody = @{
        model = $VisionModel
        stream = $false
        options = @{
            num_predict = 48
            temperature = 0
        }
        messages = @(
            @{
                role = "user"
                content = $prompt
                images = @($imageBase64)
            }
        )
    } | ConvertTo-Json -Depth 8 -Compress

    $visionResp = Invoke-OllamaChatJson -Url $chatUrl -Body $visionBody
    $visionParsed = $null
    try { $visionParsed = $visionResp.body | ConvertFrom-Json -Depth 20 } catch {}

    $result.tests += [ordered]@{
        model = $VisionModel
        category = "vision-control"
        httpStatus = $visionResp.statusCode
        success = $visionResp.isSuccess
        responsePreview = if ($visionParsed -and $visionParsed.message) { [string]$visionParsed.message.content } else { $visionResp.body.Substring(0, [Math]::Min(400, $visionResp.body.Length)) }
        acceptedImagePayload = ($visionResp.statusCode -eq 200)
    }
} else {
    $result.tests += [ordered]@{
        model = $VisionModel
        category = "vision-control"
        skipped = $true
        reason = "Model not installed"
    }
}

foreach ($model in $NonVisionModels) {
    if (-not (Test-ModelPresent $model)) {
        $result.tests += [ordered]@{
            model = $model
            category = "non-vision"
            skipped = $true
            reason = "Model not installed"
        }
        continue
    }

    $body = @{
        model = $model
        stream = $false
        options = @{
            num_predict = 48
            temperature = 0
        }
        messages = @(
            @{
                role = "user"
                content = $prompt
                images = @($imageBase64)
            }
        )
    } | ConvertTo-Json -Depth 8 -Compress

    $resp = Invoke-OllamaChatJson -Url $chatUrl -Body $body
    $parsed = $null
    try { $parsed = $resp.body | ConvertFrom-Json -Depth 20 } catch {}

    $content = if ($parsed -and $parsed.message) { [string]$parsed.message.content } else { $resp.body.Substring(0, [Math]::Min(400, $resp.body.Length)) }
    $looksVisionCapable = $content -match 'screenshot|window|desktop|code|editor|image|screen'

    $result.tests += [ordered]@{
        model = $model
        category = "non-vision"
        httpStatus = $resp.statusCode
        success = $resp.isSuccess
        responsePreview = $content
        acceptedImagePayload = ($resp.statusCode -eq 200)
        appearsToActuallyUseVision = [bool]$looksVisionCapable
    }
}

$nonVisionPositive = @($result.tests | Where-Object {
    $_.category -eq 'non-vision' -and $_.success -eq $true -and $_.appearsToActuallyUseVision -eq $true
}).Count

$result.hotpatchVisionForNonVisionModelsObserved = ($nonVisionPositive -gt 0)
if (-not $result.hotpatchVisionForNonVisionModelsObserved) {
    $result.ok = $true
}

$result | ConvertTo-Json -Depth 10 | Set-Content -Path $ReportPath -Encoding UTF8
Write-Host "Wrote report: $ReportPath"
Get-Content -Path $ReportPath
