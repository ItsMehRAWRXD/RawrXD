#requires -Version 5.1
<#
.SYNOPSIS
  Enriches models/acquisition.json with source URL, revision and license metadata
  for recognised model families (M-CFG-08). Does not re-hash models.
#>
[CmdletBinding()]
param(
    [string]$AcquisitionPath
)
$ErrorActionPreference = 'Stop'
if (-not $AcquisitionPath) {
    $base = if ($PSScriptRoot) { $PSScriptRoot } else { (Get-Location).Path }
    $AcquisitionPath = Join-Path $base '..\models\acquisition.json'
}
if (-not (Test-Path $AcquisitionPath)) { throw "missing $AcquisitionPath" }

$rules = @(
    @{ pattern = 'tinyllama'; url = 'https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF'; license = 'Apache-2.0' }
    @{ pattern = 'qwen2.5'; url = 'https://huggingface.co/Qwen/Qwen2.5-Coder-7B-Instruct-GGUF'; license = 'Apache-2.0' }
    @{ pattern = 'qwen3'; url = 'https://huggingface.co/Qwen/Qwen3-8B-GGUF'; license = 'Apache-2.0' }
    @{ pattern = 'deepseek'; url = 'https://huggingface.co/deepseek-ai/deepseek-coder-6.7B-instruct-GGUF'; license = 'MIT' }
    @{ pattern = 'nemotron'; url = 'https://huggingface.co/nvidia/Llama-3_3-Nemotron-Super-49B-v1-GGUF'; license = 'NVIDIA Open Model License' }
    @{ pattern = 'gemma'; url = 'https://huggingface.co/google/gemma-3-4b-it-GGUF'; license = 'Gemma Terms of Use' }
    @{ pattern = 'gpt-oss'; url = 'https://huggingface.co/openai/gpt-oss-20b-GGUF'; license = 'Apache-2.0' }
    @{ pattern = 'starcoder'; url = 'https://huggingface.co/bigcode/starcoder2-15b-GGUF'; license = 'BigCode OpenRAIL-M' }
)

$doc = Get-Content -LiteralPath $AcquisitionPath -Raw | ConvertFrom-Json
foreach ($e in $doc.entries) {
    foreach ($r in $rules) {
        if ($e.path -match $r.pattern) {
            $e.source_url = $r.url
            $e.license = $r.license
            $e.revision = 'main'
            break
        }
    }
}
$doc | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $AcquisitionPath -Encoding UTF8
Write-Host "Enriched $($doc.entries.Count) acquisition entries"