param(
    [ValidateSet('row4','row8')][string]$Tile = 'row8',
    [string]$Glslc = $env:GLSLC
)

$ErrorActionPreference = 'Stop'
if (-not $Glslc) { $Glslc = 'glslc.exe' }
$root = Split-Path -Parent $PSScriptRoot
$src = Join-Path $PSScriptRoot ("quant_dot_{0}.comp" -f $Tile)
if (-not (Test-Path -LiteralPath $src)) { throw "Missing shader source: $src" }

# Capability IDs are the IDs used by QuantKindOf/quant_dot_dispatch.cpp.
$kinds = [ordered]@{ q4k = 0; q6k = 1; q2k = 5; q3k = 6; q5k = 8 }
foreach ($entry in $kinds.GetEnumerator()) {
    $out = Join-Path $PSScriptRoot ("quant_dot_{0}_{1}_specialized.spv" -f $Tile, $entry.Key)
    & $Glslc -O --target-env=vulkan1.2 ("-DDEEP2_SPECIALIZED_KIND={0}" -f $entry.Value) $src -o $out
    if ($LASTEXITCODE -ne 0) { throw "glslc failed for $($entry.Key) (exit $LASTEXITCODE)" }
    if (-not (Test-Path -LiteralPath $out)) { throw "glslc produced no output: $out" }
    Write-Host ("built {0} ({1} bytes)" -f $out, (Get-Item -LiteralPath $out).Length)
}
