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
if ($variant -notin @('hoist_scale', 'half_load', 'hoist_scale_half_load', 'skip_unused_batch_rows')) {
    throw "Unsupported Q6 algebra variant: $variant"
}

$shaderPath = Join-Path $root $shaderRelative
$spvPath = Join-Path $root $spvRelative
$shader = [System.IO.File]::ReadAllText($shaderPath)
$start = $shader.IndexOf('void q6kDot4(')
if ($start -lt 0) { throw 'Q6 dot function was not found.' }
$end = $shader.IndexOf("`nvoid main()", $start)
if ($end -lt 0) { throw 'Q6 dot function boundary was not found.' }
$prefix = $shader.Substring(0, $start)
$body = $shader.Substring($start, $end - $start)
$suffix = $shader.Substring($end)

if ($variant -in @('half_load', 'hoist_scale_half_load')) {
    $old = '    float d=geth(b+208u);'
    $new = '    float d=unpackHalf2x16(w[(b+208u)>>2u])[((b+208u)&2u)>>1u];'
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

$fullShader = $prefix + $body + $suffix
if ($variant -eq 'skip_unused_batch_rows') {
    $newLoads = @'
        if(c<pc.cols) {
            xs[0][lid]=x[c];
            if(pc.batch>1u) xs[1][lid]=x[pc.cols+c];
            if(pc.batch>2u) xs[2][lid]=x[2u*pc.cols+c];
            if(pc.batch>3u) xs[3][lid]=x[3u*pc.cols+c];
        } else {
            xs[0][lid]=0.0;
            if(pc.batch>1u) xs[1][lid]=0.0;
            if(pc.batch>2u) xs[2][lid]=0.0;
            if(pc.batch>3u) xs[3][lid]=0.0;
        }
'@
    $loadPattern = '(?s)        if\(c<pc\.cols\) \{\s+xs\[0\]\[lid\]=x\[c\];\s+xs\[1\]\[lid\]=pc\.batch>1u\?x\[pc\.cols\+c\]:0\.0;\s+xs\[2\]\[lid\]=pc\.batch>2u\?x\[2u\*pc\.cols\+c\]:0\.0;\s+xs\[3\]\[lid\]=pc\.batch>3u\?x\[3u\*pc\.cols\+c\]:0\.0;\s+\} else \{\s+xs\[0\]\[lid\]=xs\[1\]\[lid\]=xs\[2\]\[lid\]=xs\[3\]\[lid\]=0\.0;\s+\}'
    if (-not [regex]::IsMatch($fullShader, $loadPattern)) { throw 'Q6 activation load block was not found.' }
    $fullShader = [regex]::Replace($fullShader, $loadPattern, $newLoads.Trim(), 1)
}

if ($fullShader -ceq $shader) { throw 'Mutation produced no shader change.' }
$glslc = Join-Path ($env:VULKAN_SDK ? $env:VULKAN_SDK : 'C:\VulkanSDK\1.4.357.0') 'Bin\glslc.exe'
if (-not (Test-Path -LiteralPath $glslc -PathType Leaf)) { throw "glslc not found: $glslc" }
[System.IO.File]::WriteAllText(
    $shaderPath,
    $fullShader,
    [System.Text.UTF8Encoding]::new($false))

& $glslc -O --target-env=vulkan1.2 -fshader-stage=compute $shaderPath -o $spvPath 2>&1
if ($LASTEXITCODE -ne 0) { throw "glslc failed with exit $LASTEXITCODE." }
