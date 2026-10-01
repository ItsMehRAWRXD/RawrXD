<#
.SYNOPSIS
    Generates a bounded, response-coded RawrXD agent script from a template.

.DESCRIPTION
    Writes a ready-to-run PowerShell agent that follows exactly this contract:

        USER -> MODEL -> optional authorized tool -> SAME MODEL -> RESPONSE -> STOP

    The model never supplies PowerShell. It may only name one whitelisted
    read-only capability; the host maps that name to a command. There is no
    autonomous loop, no background work, no scheduler, and no mutation.

    The template lives next to this script, so the generated file contains no
    nested here-string escaping hazards.

.PARAMETER Model
    Anything the resolver understands: an Ollama reference, an alias, or a
    GGUF path.

.PARAMETER RawrPath
    Path to rawr.exe.

.PARAMETER RepoRoot
    Repository the read-only tools operate on.

.PARAMETER OutPath
    Where to write the generated agent script.

.EXAMPLE
    ./New-RawrResponseAgent.ps1 -Model llama3.2:3b
    ./New-RawrResponseAgent.ps1 -Model qwen2.5-coder:1.5b-base -OutPath .\agent.ps1
#>
[CmdletBinding()]
param(
    [string]$Model    = 'qwen2.5-coder:1.5b-base',
    [string]$RawrPath = 'C:\Users\Garrett\rawrxd\bin\rawr.exe',
    [string]$RepoRoot = 'F:\~dev\rawrxd',
    [string]$OutPath  = 'F:\~dev\rawrxd\tools\rawr_response_agent.ps1',
    [int]   $Tokens   = 192
)

$ErrorActionPreference = 'Stop'

$template = Join-Path $PSScriptRoot 'rawr_response_agent.template.ps1'
if (-not (Test-Path -LiteralPath $template)) { throw "template not found: $template" }
if (-not (Test-Path -LiteralPath $RawrPath))  { throw "rawr.exe not found: $RawrPath" }
if (-not (Test-Path -LiteralPath $RepoRoot))  { throw "repo not found: $RepoRoot" }

$text = [System.IO.File]::ReadAllText($template)
$text = $text.Replace('__RAWR__',   $RawrPath)
$text = $text.Replace('__MODEL__',  $Model)
$text = $text.Replace('__REPO__',   $RepoRoot)
$text = $text.Replace('__TOKENS__', ([string]$Tokens))

if ($text -match '__[A-Z]+__') { throw 'unsubstituted placeholder remains in template' }

$outDir = Split-Path -Parent $OutPath
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
    New-Item -ItemType Directory -Force -Path $outDir | Out-Null
}
Set-Content -LiteralPath $OutPath -Value $text -Encoding UTF8

# Parse-check the generated script so a broken generation is caught here,
# not at first use.
$errors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile($OutPath, [ref]$null, [ref]$errors)
if ($errors -and $errors.Count -gt 0) {
    Write-Host "GENERATED SCRIPT HAS PARSE ERRORS:" -ForegroundColor Red
    $errors | ForEach-Object { Write-Host "  $($_.Extent.StartLineNumber): $($_.Message)" -ForegroundColor Red }
    throw "generated script failed to parse"
}

Write-Host "GENERATED: $OutPath" -ForegroundColor Green
Write-Host "  model  : $Model"
Write-Host "  rawr   : $RawrPath"
Write-Host "  repo   : $RepoRoot"
Write-Host "  tokens : $Tokens"
Write-Host "  parsed : OK"
Write-Host ""
Write-Host "Run it with:"
Write-Host "  . '$OutPath'"
Write-Host "  Invoke-RawrResponse 'What branch am I on and is the worktree clean?'"
