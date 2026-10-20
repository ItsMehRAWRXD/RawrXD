Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = [System.IO.Path]::GetFullPath($env:RAWRXD_MUTATION_ROOT)
$allowed = @($env:RAWRXD_MUTATION_ALLOWED_FILES -split ';')
$shaderRelative = 'rawrxd/src/deep2/shaders/deep2_qgemv_batch8row.comp'
$spvRelative = 'rawrxd/src/deep2/shaders/deep2_qgemv_batch8row.spv'
if ($shaderRelative -notin $allowed -or $spvRelative -notin $allowed) {
    throw 'Q6 algebra mutation requires the shader and generated SPIR-V to be declared.'
}

$variant = if ($env:RAWRXD_MUTATION_VARIANT) { $env:RAWRXD_MUTATION_VARIANT } else { 'hoist_scale' }
if ($variant -notin @('hoist_scale', 'half_load', 'hoist_scale_half_load')) {
    throw "Unsupported Q6 algebra variant: $variant"
}

$shaderPath = Join-Path $root $shaderRelative
$spvPath = Join-Path $root $spvRelative
$shader = [System.IO.File]::ReadAllText($shaderPath)
$start = $shader.IndexOf('void q6kDot4(')
$end = $shader.IndexOf("`nvoid main()", $start)
if ($start -lt 0 -or $end -lt 0) { throw 'Q6 dot function was not found.' }
$prefix = $shader.Substring(0, $start)
$body = $shader.Substring($start, $end - $start)
$suffix = $shader.Substring($end)

if ($variant -in @('half_load', 'hoist_scale_half_load')) {
    $old = '    float d=geth(b+208u);'
    $new = '    float d=unpackHalf2x16(load4Bytes(b+208u)).x;'
    if ($body.IndexOf($old, [System.StringComparison]::Ordinal) -lt 0) { throw 'Q6 scale load was not found.' }
    $body = $body.Replace($old, $new)
}

if ($variant -in @('hoist_scale', 'hoist_scale_half_load')) {
    $oldScale = '    float scale=float(gets8(b+192u+scaleIndex));'
    $newScale = "    float scale=float(gets8(b+192u+scaleIndex));`n    float ds=d*scale;"
    if ($body.IndexOf($oldScale, [System.StringComparison]::Ordinal) -lt 0) { throw 'Q6 scale expression was not found.' }
    $body = $body.Replace($oldScale, $newScale)
    $oldWeight = '        float ww=d*scale*float(int(q|(high<<4u))-32);'
    $newWeight = '        float ww=ds*float(int(q|(high<<4u))-32);'
    if ($body.IndexOf($oldWeight, [System.StringComparison]::Ordinal) -lt 0) { throw 'Q6 weight expression was not found.' }
    $body = $body.Replace($oldWeight, $newWeight)
}

[System.IO.File]::WriteAllText(
    $shaderPath,
    $prefix + $body + $suffix,
    [System.Text.UTF8Encoding]::new($false))

$glslc = Join-Path ($env:VULKAN_SDK ? $env:VULKAN_SDK : 'C:\VulkanSDK\1.4.357.0') 'Bin\glslc.exe'
if (-not (Test-Path -LiteralPath $glslc -PathType Leaf)) { throw "glslc not found: $glslc" }
& $glslc -O --target-env=vulkan1.2 -fshader-stage=compute $shaderPath -o $spvPath 2>&1
if ($LASTEXITCODE -ne 0) { throw "glslc failed with exit $LASTEXITCODE." }
