param(
    [string]$ShaderDir = (Join-Path $PSScriptRoot "shaders")
)
$ErrorActionPreference = "Stop"

$glslc = $null
if ($env:VULKAN_SDK) {
    foreach ($p in @(
        (Join-Path $env:VULKAN_SDK "Bin\glslc.exe"),
        (Join-Path $env:VULKAN_SDK "Bin\glslangValidator.exe")
    )) {
        if (Test-Path $p) { $glslc = $p; break }
    }
}
if (-not $glslc) {
    $cmd = Get-Command glslc.exe -ErrorAction SilentlyContinue
    if ($cmd) { $glslc = $cmd.Source }
}
if (-not $glslc) {
    throw "Vulkan shader compiler not found. Set VULKAN_SDK."
}

function Compile-One([string]$src, [string]$dst) {
    if ($glslc.EndsWith("glslangValidator.exe")) {
        & $glslc -V --target-env vulkan1.2 -S comp $src -o $dst
    } else {
        & $glslc -O --target-env=vulkan1.2 -fshader-stage=compute $src -o $dst
    }
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $dst)) {
        throw "Shader compile failed: $src"
    }
}

Compile-One (Join-Path $ShaderDir "deep2_ops.comp") `
            (Join-Path $ShaderDir "deep2_ops.spv")
Compile-One (Join-Path $ShaderDir "deep2_qgemv.comp") `
            (Join-Path $ShaderDir "deep2_qgemv.spv")
Compile-One (Join-Path $ShaderDir "deep2_qgemv_batch.comp") `
            (Join-Path $ShaderDir "deep2_qgemv_batch.spv")
Compile-One (Join-Path $ShaderDir "deep2_qgemv_batch4row.comp") `
            (Join-Path $ShaderDir "deep2_qgemv_batch4row.spv")
Compile-One (Join-Path $ShaderDir "deep2_qgemv_batch8row.comp") `
            (Join-Path $ShaderDir "deep2_qgemv_batch8row.spv")

Compile-One (Join-Path $ShaderDir "deep2_argmax.comp") `
            (Join-Path $ShaderDir "deep2_argmax.spv")
Compile-One (Join-Path $ShaderDir "deep2_spec_ops.comp") `
            (Join-Path $ShaderDir "deep2_spec_ops.spv")
Compile-One (Join-Path $ShaderDir "deep2_spec_attn.comp") `
            (Join-Path $ShaderDir "deep2_spec_attn.spv")

Write-Host "BATCH9_SHADER_BUILD=PASS"

Compile-One (Join-Path $ShaderDir "deep2_spec_accept.comp") `
            (Join-Path $ShaderDir "deep2_spec_accept.spv")
