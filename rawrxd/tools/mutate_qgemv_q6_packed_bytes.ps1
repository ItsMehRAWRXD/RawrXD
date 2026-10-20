Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$root = [System.IO.Path]::GetFullPath($env:RAWRXD_MUTATION_ROOT)
$allowed = @($env:RAWRXD_MUTATION_ALLOWED_FILES -split ';')
$shaderRelative = 'rawrxd/src/deep2/shaders/deep2_qgemv_batch8row.comp'
$spvRelative = 'rawrxd/src/deep2/shaders/deep2_qgemv_batch8row.spv'
if ($shaderRelative -notin $allowed -or $spvRelative -notin $allowed) {
    throw 'Q6 packed-byte mutation requires the shader and generated SPIR-V to be declared.'
}

$shaderPath = Join-Path $root $shaderRelative
$spvPath = Join-Path $root $spvRelative
$shader = [System.IO.File]::ReadAllText($shaderPath)
$pattern = '(?s)void q6kDot4\(uint rowBase,uint globalCol,uint localCol,.*?\r?\n\}\r?\n\r?\nvoid main\(\)'
$replacement = @'
uint load4Bytes(uint byteIndex) {
    uint wordIndex=byteIndex>>2u;
    uint shift=(byteIndex&3u)*8u;
    uint lo=w[wordIndex];
    if(shift==0u) return lo;
    uint hi=w[wordIndex+1u];
    return (lo>>shift)|(hi<<(32u-shift));
}

void q6kDot4(uint rowBase,uint globalCol,uint localCol,
             inout float a0,inout float a1,inout float a2,inout float a3) {
    uint block=globalCol>>8u;
    uint element=globalCol&255u;
    uint elementHalf=element>>7u;
    uint elementWithin=element&127u;
    uint elementCat=elementWithin>>5u;
    uint elementL=elementWithin&31u;
    uint b=rowBase+block*210u;
    uint qlBase=b+elementHalf*64u+(elementCat&1u)*32u+elementL;
    uint qhBase=b+128u+elementHalf*32u+elementL;
    uint ql=load4Bytes(qlBase);
    uint qh=load4Bytes(qhBase);
    uint scaleIndex=elementHalf*8u+(elementCat<<1u)+(elementL>>4u);
    float d=geth(b+208u);
    float scale=float(gets8(b+192u+scaleIndex));
    for(uint k=0u;k<4u;++k) {
        uint col=globalCol+k;
        if(col>=pc.cols) break;
        uint qByte=(ql>>(k*8u))&255u;
        uint q=(elementCat&1u)==0u?(qByte&15u):(qByte>>4u);
        uint highByte=(qh>>(k*8u))&255u;
        uint high=(highByte>>((elementCat&3u)*2u))&3u;
        float ww=d*scale*float(int(q|(high<<4u))-32);
        uint local=localCol+k;
        a0+=ww*xs[0][local];
        if(pc.batch>1u) a1+=ww*xs[1][local];
        if(pc.batch>2u) a2+=ww*xs[2][local];
        if(pc.batch>3u) a3+=ww*xs[3][local];
    }
}

void main()
'@
if (-not [regex]::IsMatch($shader, $pattern)) { throw 'Q6 dot function was not found.' }
$shader = [regex]::Replace($shader, $pattern, $replacement.TrimEnd(), 1)
[System.IO.File]::WriteAllText($shaderPath, $shader, [System.Text.UTF8Encoding]::new($false))

$glslc = Join-Path ($env:VULKAN_SDK ? $env:VULKAN_SDK : 'C:\VulkanSDK\1.4.357.0') 'Bin\glslc.exe'
if (-not (Test-Path -LiteralPath $glslc -PathType Leaf)) { throw "glslc not found: $glslc" }
& $glslc -O --target-env=vulkan1.2 -fshader-stage=compute $shaderPath -o $spvPath 2>&1
if ($LASTEXITCODE -ne 0) { throw "glslc failed with exit $LASTEXITCODE." }
