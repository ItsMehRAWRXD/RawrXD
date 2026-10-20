Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = [System.IO.Path]::GetFullPath($env:RAWRXD_MUTATION_ROOT)
$variant = if ($env:RAWRXD_MUTATION_VARIANT) { $env:RAWRXD_MUTATION_VARIANT } else { 'scalar-two-row' }
if ($variant -ne 'scalar-two-row') { throw "Unsupported QGEMV mutation variant: $variant" }
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
$mainStart = $shader.IndexOf('void main()', [System.StringComparison]::Ordinal)
if ($mainStart -lt 0) { throw 'Shader main function was not found.' }

$main = @'
void main() {
    if((pc.type!=12u&&pc.type!=14u)||pc.batch==0u||pc.batch>4u||pc.cols==0u) return;

    uint lid=gl_LocalInvocationID.x;
    uint subgroupSize=gl_SubgroupSize;
    uint lane=gl_SubgroupInvocationID;
    uint rowGroup=gl_WorkGroupID.x*gl_NumSubgroups*2u;
    uint blocks=(pc.cols+255u)>>8u;
    uint rowBytes=blocks*(pc.type==14u?210u:144u);

    for(uint blk=0u;blk<blocks;++blk) {
        uint colBase=blk*256u;
        uint c=colBase+lid;
        if(c<pc.cols) {
            xs[0][lid]=x[c];
            xs[1][lid]=pc.batch>1u?x[pc.cols+c]:0.0;
            xs[2][lid]=pc.batch>2u?x[2u*pc.cols+c]:0.0;
            xs[3][lid]=pc.batch>3u?x[3u*pc.cols+c]:0.0;
        } else {
            xs[0][lid]=xs[1][lid]=xs[2][lid]=xs[3][lid]=0.0;
        }
        barrier();

        for(uint pass=0u;pass<2u;++pass) {
            uint row=rowGroup+pass*gl_NumSubgroups+gl_SubgroupID;
            float a0=0.0,a1=0.0,a2=0.0,a3=0.0;
            if(row<pc.rows && subgroupSize <= 256u &&
               (256u % subgroupSize) == 0u) {
                uint rb=row*rowBytes;
                uint valuesPerLane=256u/subgroupSize;
                if(pc.type==14u) {
                    for(uint k=0u;k<valuesPerLane;k+=4u) {
                        uint lc=lane*valuesPerLane+k;
                        uint gc=colBase+lc;
                        if(gc>=pc.cols) continue;
                        q6kDot4(rb,gc,lc,a0,a1,a2,a3);
                    }
                } else {
                    for(uint k=0u;k<valuesPerLane;k+=4u) {
                        uint lc=lane*valuesPerLane+k;
                        uint gc=colBase+lc;
                        if(gc<pc.cols)
                            q4kDot4(rb,gc,lc,a0,a1,a2,a3);
                    }
                }
            }
            float t0=subgroupAdd(a0);
            float t1=subgroupAdd(a1);
            float t2=subgroupAdd(a2);
            float t3=subgroupAdd(a3);
            if(subgroupElect()&&row<pc.rows) {
                y[row]=t0;
                if(pc.batch>1u)y[pc.rows+row]=t1;
                if(pc.batch>2u)y[2u*pc.rows+row]=t2;
                if(pc.batch>3u)y[3u*pc.rows+row]=t3;
            }
        }
        barrier();
    }
}
'@
$shader = $shader.Substring(0, $mainStart) + $main
[System.IO.File]::WriteAllText($shaderPath, $shader, [System.Text.UTF8Encoding]::new($false))

$header = [System.IO.File]::ReadAllText($headerPath)
$new = @'
    uint32_t batchRowsPerWorkgroup() const noexcept {
        return subgroupSize_ && (256u % subgroupSize_) == 0u
            ? 512u / subgroupSize_ : 1u;
    }
'@
$pattern = '(?s)    uint32_t batchRowsPerWorkgroup\(\) const noexcept \{\r?\n.*?    \}'
if (-not [regex]::IsMatch($header, $pattern)) { throw 'Expected batchRowsPerWorkgroup baseline was not found.' }
$header = [regex]::Replace($header, $pattern, $new.TrimEnd())
[System.IO.File]::WriteAllText($headerPath, $header, [System.Text.UTF8Encoding]::new($false))

$glslc = Join-Path ($env:VULKAN_SDK ? $env:VULKAN_SDK : 'C:\VulkanSDK\1.4.357.0') 'Bin\glslc.exe'
if (-not (Test-Path -LiteralPath $glslc -PathType Leaf)) { throw "glslc not found: $glslc" }
& $glslc -O --target-env=vulkan1.2 -fshader-stage=compute $shaderPath -o $spvPath 2>&1
if ($LASTEXITCODE -ne 0) { throw "glslc failed with exit $LASTEXITCODE." }
