Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = [System.IO.Path]::GetFullPath($env:RAWRXD_MUTATION_ROOT)
$variant = if ($env:RAWRXD_MUTATION_VARIANT) { $env:RAWRXD_MUTATION_VARIANT } else { 'wide-workgroup' }
if ($variant -ne 'wide-workgroup') { throw "Unsupported QGEMV mutation variant: $variant" }
$allowed = @($env:RAWRXD_MUTATION_ALLOWED_FILES -split ';')
$required = @(
    'rawrxd/src/deep2/shaders/deep2_qgemv_batch8row.comp',
    'rawrxd/src/deep2/shaders/deep2_qgemv_batch8row.spv',
    'rawrxd/src/deep2/vulkan_compute.h'
)
foreach ($path in $required) {
    if ($path -notin $allowed) { throw "Mutation file is not declared: $path" }
}

$shaderPath = Join-Path $root 'rawrxd/src/deep2/shaders/deep2_qgemv_batch8row.comp'
$headerPath = Join-Path $root 'rawrxd/src/deep2/vulkan_compute.h'
$spvPath = Join-Path $root 'rawrxd/src/deep2/shaders/deep2_qgemv_batch8row.spv'
$shader = [System.IO.File]::ReadAllText($shaderPath)
if ($shader -notmatch 'layout\(local_size_x=256\) in;') { throw 'Expected 256-thread shader baseline was not found.' }
$shader = $shader.Replace('layout(local_size_x=256) in;', 'layout(local_size_x=512) in;')

$loadPattern = '(?s)        uint colBase=blk\*256u;\r?\n        uint c=colBase\+lid;\r?\n        if\(c<pc\.cols\) \{.*?        barrier\(\);'
$loadReplacement = @'
        uint colBase=blk*256u;
        if(lid<256u) {
            uint c=colBase+lid;
            if(c<pc.cols) {
                xs[0][lid]=x[c];
                xs[1][lid]=pc.batch>1u?x[pc.cols+c]:0.0;
                xs[2][lid]=pc.batch>2u?x[2u*pc.cols+c]:0.0;
                xs[3][lid]=pc.batch>3u?x[3u*pc.cols+c]:0.0;
            } else {
                xs[0][lid]=xs[1][lid]=xs[2][lid]=xs[3][lid]=0.0;
            }
        }
        barrier();
'@
if (-not [regex]::IsMatch($shader, $loadPattern)) { throw 'Activation tile load block was not found.' }
$shader = [regex]::Replace($shader, $loadPattern, $loadReplacement, 1)
[System.IO.File]::WriteAllText($shaderPath, $shader, [System.Text.UTF8Encoding]::new($false))

$header = [System.IO.File]::ReadAllText($headerPath)
$headerPattern = '(?s)    uint32_t batchRowsPerWorkgroup\(\) const noexcept \{\r?\n.*?    \}'
$headerReplacement = @'
    uint32_t batchRowsPerWorkgroup() const noexcept {
        return subgroupSize_ && (256u % subgroupSize_) == 0u
            ? 512u / subgroupSize_ : 1u;
    }
'@
if (-not [regex]::IsMatch($header, $headerPattern)) { throw 'batchRowsPerWorkgroup was not found.' }
$header = [regex]::Replace($header, $headerPattern, $headerReplacement.TrimEnd(), 1)
[System.IO.File]::WriteAllText($headerPath, $header, [System.Text.UTF8Encoding]::new($false))

$glslc = Join-Path ($env:VULKAN_SDK ? $env:VULKAN_SDK : 'C:\VulkanSDK\1.4.357.0') 'Bin\glslc.exe'
if (-not (Test-Path -LiteralPath $glslc -PathType Leaf)) { throw "glslc not found: $glslc" }
& $glslc -O --target-env=vulkan1.2 -fshader-stage=compute $shaderPath -o $spvPath 2>&1
if ($LASTEXITCODE -ne 0) { throw "glslc failed with exit $LASTEXITCODE." }
