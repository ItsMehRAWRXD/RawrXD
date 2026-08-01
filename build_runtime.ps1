# build_runtime.ps1 — Build RawrXD Runtime Engine
# Runs ml64.exe + link.exe directly, no C++ compiler needed.

$Root = "D:\rawrxd-ci-bootstrap"
$ML64 = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
$LINK = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe"
$ObjDir = "$Root\build\obj"
$BinDir = "$Root\build\bin"
$SrcDir = "$Root\src"

$MasmFlags = @("/nologo", "/c", "/Cx", "/Zi",
    "/I$SrcDir",
    "/I$SrcDir\runtime",
    "/I$SrcDir\model",
    "/I$SrcDir\gguf",
    "/I$SrcDir\tokenizer",
    "/I$SrcDir\agent",
    "/I$SrcDir\gpu",
    "/I$SrcDir\agentic",
    "/I$Root\tests")

$LinkLibs = @("kernel32.lib","user32.lib","gdi32.lib","advapi32.lib","shell32.lib","shlwapi.lib","ucrt.lib")
$LinkFlags = @("/nologo", "/MACHINE:X64", "/SUBSYSTEM:CONSOLE")

# SDK paths
$SDKRoot = "C:\Program Files (x86)\Windows Kits\10"
$SDKVerUC = "10.0.22621.0"
$SDKVerUM = "10.0.26100.0"
$MSVCLib = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64"

# Clean
if ($args[0] -eq "clean") {
    Remove-Item -Recurse -Force $ObjDir -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $BinDir -ErrorAction SilentlyContinue
    Write-Host "Cleaned." -ForegroundColor Green
    exit 0
}

# Create dirs
New-Item -ItemType Directory -Force -Path $ObjDir, $BinDir | Out-Null

# Files to assemble: [source_path, obj_name]
$Files = @(
    ,@("$SrcDir\runtime\kernel_registry.asm",   "kernel_registry.obj")
    ,@("$SrcDir\runtime\tensor.asm",            "tensor.obj")
    ,@("$SrcDir\runtime\q4_matmul.asm",         "q4_matmul.obj")
    ,@("$SrcDir\runtime\kv_cache.asm",          "kv_cache.obj")
    ,@("$SrcDir\runtime\sampler.asm",           "sampler.obj")
    ,@("$SrcDir\runtime\inference_engine.asm",  "inference_engine.obj")
    ,@("$SrcDir\model\transformer_block.asm",   "transformer_block.obj")
    ,@("$SrcDir\gguf\gguf_reader.asm",          "gguf_reader.obj")
    ,@("$SrcDir\tokenizer\bpe.asm",             "bpe.obj")
    ,@("$SrcDir\agent\agent_runtime.asm",       "agent_runtime.obj")
    ,@("$SrcDir\gpu\gpu_backend.asm",           "gpu_backend.obj")
    ,@("$Root\tests\runtime_smoke.asm",         "runtime_smoke.obj")
)

$Objs = @()
foreach ($f in $Files) {
    $src = $f[0]
    $obj = $f[1]
    $objPath = "$ObjDir\$obj"
    $args = $MasmFlags + @("/Fo$objPath", $src)
    Write-Host "ASM $([System.IO.Path]::GetFileName($src))" -NoNewline
    & $ML64 $args 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "  OK" -ForegroundColor Green
        $Objs += $objPath
    } else {
        Write-Host "  FAILED (exit $LASTEXITCODE)" -ForegroundColor Red
        & $ML64 $args
        exit 1
    }
}

# Link
Write-Host "LINK runtime_smoke.exe" -NoNewline
$rsp = Join-Path $env:TEMP "rawrxd_link.rsp"
$content = @()
$content += $LinkFlags
$content += "/OUT:`"$BinDir\runtime_smoke.exe`""
foreach ($obj in $Objs) { $content += "`"$obj`"" }
$content += $LinkLibs
$content += "-LIBPATH:`"$MSVCLib`""
$content += "-LIBPATH:`"$SDKRoot\Lib\$SDKVerUC\ucrt\x64`""
$content += "-LIBPATH:`"$SDKRoot\Lib\$SDKVerUM\um\x64`""
$content -join "`r`n" | Out-File -FilePath $rsp -Encoding ASCII -Force

& $LINK "@$rsp"
if ($LASTEXITCODE -eq 0) {
    Write-Host "  OK" -ForegroundColor Green
    $size = (Get-Item "$BinDir\runtime_smoke.exe").Length
    Write-Host "Built: runtime_smoke.exe ($size bytes)" -ForegroundColor Green
} else {
    Write-Host "  FAILED (exit $LASTEXITCODE)" -ForegroundColor Red
    Get-Content $rsp
    exit 1
}
Remove-Item -Force $rsp -ErrorAction SilentlyContinue
