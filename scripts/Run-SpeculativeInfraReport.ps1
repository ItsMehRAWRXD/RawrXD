#Requires -Version 5.1
<#!
.SYNOPSIS
  Generates an institutional speculative benchmark report bundle from
  RawrXD-ComparativeBenchmark.json.

.EXAMPLE
  .\Run-SpeculativeInfraReport.ps1

.EXAMPLE
  .\Run-SpeculativeInfraReport.ps1 -InputJson D:\rawrxd\build-ninja\RawrXD-ComparativeBenchmark.json -OutDir D:\rawrxd\reports\speculative_infra
#>
param(
    [string]$InputJson = "D:\rawrxd\build-ninja\RawrXD-ComparativeBenchmark.json",
    [string]$OutDir = "D:\rawrxd\reports\speculative_infra",
    [string]$BenchDir = "",
    [switch]$NoPdf
)

$ErrorActionPreference = "Stop"
$py = Join-Path $PSScriptRoot "speculative_infra_report.py"

if (-not (Test-Path -LiteralPath $InputJson)) {
    throw "Input JSON not found: $InputJson"
}
if (-not (Test-Path -LiteralPath $py)) {
    throw "Missing script: $py"
}

$args = @($py, "--input", $InputJson, "--out-dir", $OutDir)
if ($NoPdf) {
    $args += "--no-pdf"
}
if ($BenchDir -and (Test-Path $BenchDir)) {
    $args += @("--bench-dir", $BenchDir)
}

& python @args
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}
