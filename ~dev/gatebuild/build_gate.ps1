# build_gate.ps1 — compile the Deep2 engine core + one gate test, link, run.
param(
    [Parameter(Mandatory=$true)][string]$Name,
    [Parameter(Mandatory=$true)][string]$Src,
    [switch]$Run = $false,
    [string]$Args = "",
    [switch]$SkipEngine = $false
)
$ErrorActionPreference = "Stop"

$Dev   = "F:\rawrxd\~dev"
$Gate  = "$Dev\gatebuild"
$Core  = "$Gate\obj_core"
$Test  = "$Gate\obj_$Name"
$Vk    = "C:\VulkanSDK\1.4.357.0"
$Exe   = "$Gate\$Name.exe"

New-Item -ItemType Directory -Path $Gate,$Core,$Test -Force | Out-Null

$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$vsPath  = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
$vcvars  = Join-Path $vsPath "Common7\Tools\VsDevCmd.bat"

$Inc = @(
    "/I$Dev", "/I$Dev\rawrxd\src", "/I$Dev\rawrxd\src\deep2",
    "/I$Dev\rawrxd\include", "/I$Dev\rawrxd\src\masm", "/I$Vk\Include",
    "/I$Dev\src", "/I$Dev\src\deep2"
)
$Defs = @(
    "/DRAWRXD_DEEP2_CERT=1","/DRAWR_STANDALONE_INFERENCE=1","/DRAWR_HAS_SOVEREIGN_ENGINES=1",
    "/DRAWR_HAS_VULKAN=1","/DRAWR_VULKAN_AVAILABLE=1",
    "/DRAWRXD_STRICT_PRODUCTION_PROFILE=0","/DRAWRXD_PRODUCTION_STRIP_STUB_SOURCES=0",
    "/DNOMINMAX","/DWIN32_LEAN_AND_MEAN"
)
$Flags = @("/nologo","/std:c++17","/O2","/arch:AVX512","/EHsc","/c","/MP") + $Inc + $Defs

function Invoke-Bat([string]$content) {
    $tmp = Join-Path $Gate "_step.bat"
    Set-Content -LiteralPath $tmp -Value $content
    & cmd /c $tmp 2>&1
}

if (-not $SkipEngine) {
    $coreSrcs = @(
        "Deep2Engine","Deep2Engine_Speculative","Deep2Engine_GpuForward","Deep2Engine_GpuMoEMLA",
        "Deep2Engine_SsVkDecodeBind","Deep2Engine_VulkanRuntime","Deep2DualGpuRowSplit",
        "QuantKernelRegistry","Tokenizer","vulkan_compute","Sampler",
        "Deep2RooflineRuntime","Deep2MultiGpuLayerPlan","Deep2RooflineGovernor","Deep2RooflineCert",
        "Deep2CommandBatch","Deep2ExpertResidency","Deep2PredictiveRouter","Deep2PersistentDecode",
        "Deep2DualGpuBalancer","K2LogitsClimb","K2VNNIKernel","K2LivePathTensorCache"
    ) | ForEach-Object {
        $candidates = @(
            (Join-Path "$Dev\rawrxd\src\deep2" "$_.cpp"),
            (Join-Path "$Dev\src\deep2"        "$_.cpp")
        )
        ($candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1)
    } | Where-Object { $_ }
    Write-Host "[BUILD] engine core: $($coreSrcs.Count) sources"
    $bat = @"
@echo off
call "$vcvars" -arch=x64 -no_logo < nul
cd /d $Dev
cl $(($Flags + $coreSrcs + @("/Fo$Core\") -join ' '))
echo CORE_EXIT=%ERRORLEVEL%
"@
    $out = Invoke-Bat $bat
    $errs = $out | Where-Object { $_ -match 'error C|error LNK|CORE_EXIT=' -and $_ -notmatch 'CORE_EXIT=0' }
    if ($errs) { $errs | ForEach-Object { Write-Host $_ }; throw "engine core compile failed" }
    Write-Host "[BUILD] engine core OK"
}

$srcFull = (Resolve-Path -LiteralPath $Src).Path
$testBat = @"
@echo off
call "$vcvars" -arch=x64 -no_logo < nul
cd /d $Dev
cl $(($Flags + @($srcFull,"/Fo$Test\") -join ' '))
echo TEST_EXIT=%ERRORLEVEL%
"@
$out = Invoke-Bat $testBat
$terrs = $out | Where-Object { $_ -match 'error C|error LNK' }
if ($terrs) { $terrs | ForEach-Object { Write-Host $_ }; throw "test compile failed" }
Write-Host "[BUILD] $Name compiled"

$objs = @((Get-ChildItem $Core -Filter *.obj), (Get-ChildItem $Test -Filter *.obj)) | ForEach-Object { $_.FullName }
$libs = @("vulkan-1.lib","psapi.lib","dbghelp.lib","winhttp.lib","bcrypt.lib","advapi32.lib",
          "crypt32.lib","dxgi.lib","pdh.lib","shlwapi.lib","kernel32.lib","user32.lib",
          "gdi32.lib","ole32.lib","oleaut32.lib","uuid.lib","shell32.lib")
$linkBat = @"
@echo off
call "$vcvars" -arch=x64 -no_logo < nul
cd /d $Dev
link /nologo /OUT:"$Exe" /LIBPATH:"$Vk\Lib" $(($objs + $libs) -join ' ')
echo LINK_EXIT=%ERRORLEVEL%
"@
$lout = Invoke-Bat $linkBat
$lerrs = $lout | Where-Object { $_ -match 'LNK' }
if ($lerrs) { $lerrs | ForEach-Object { Write-Host $_ }; throw "link failed" }
Write-Host "[BUILD] $Name linked -> $Exe"

if ($Run) {
    Write-Host "[RUN] $Name $Args"
    cmd /c "`"$Exe`" $Args"
}

