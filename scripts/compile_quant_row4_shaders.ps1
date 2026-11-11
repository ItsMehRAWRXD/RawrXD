param(
    [string]$VulkanBin = "C:\VulkanSDK\1.4.357.0\Bin"
)
$ErrorActionPreference = "Stop"
$glslc = Join-Path $VulkanBin "glslc.exe"
if (-not (Test-Path -LiteralPath $glslc)) { throw "glslc.exe not found: $glslc" }
$src = (Resolve-Path (Join-Path $PSScriptRoot "..\tools\shaders\quant_dot_row4.comp")).Path
$src8 = (Resolve-Path (Join-Path $PSScriptRoot "..\tools\shaders\quant_dot_row8.comp")).Path
$outDir = Split-Path $src -Parent
& $glslc -O --target-env=vulkan1.2 $src -o (Join-Path $outDir "quant_dot_row4.spv")
if ($LASTEXITCODE -ne 0) { throw "Q4 row4 shader compile failed: $LASTEXITCODE" }
& $glslc -O --target-env=vulkan1.2 -DDEEP2_Q6_SHARED_TILE=1 $src -o (Join-Path $outDir "quant_dot_row4_q6tile.spv")
if ($LASTEXITCODE -ne 0) { throw "Q6 shared-tile shader compile failed: $LASTEXITCODE" }
& $glslc -O --target-env=vulkan1.2 $src8 -o (Join-Path $outDir "quant_dot_row8.spv")
if ($LASTEXITCODE -ne 0) { throw "Q4 row8 shader compile failed: $LASTEXITCODE" }
& $glslc -O --target-env=vulkan1.2 -DDEEP2_Q6_SHARED_TILE=1 $src8 -o (Join-Path $outDir "quant_dot_row8_q6tile.spv")
if ($LASTEXITCODE -ne 0) { throw "Q6 row8 shared-tile shader compile failed: $LASTEXITCODE" }
Write-Host "Compiled row4 and row8 quant-dot shaders (regular and Q6 shared-tile)"
