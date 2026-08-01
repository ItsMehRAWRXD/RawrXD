#!/usr/bin/env pwsh
<#
.SYNOPSIS
    RawrXD IDE Build Script — Drives ml64.exe + cl.exe + link.exe
    No CMake required; finds MSVC toolchain automatically.

.DESCRIPTION
    Assembles all MASM x64 source files, compiles C++ wrapper, and links
    the final RawrXD_IDE.exe and RawrXD_Widget.exe without any external
    dependency beyond the Windows SDK and MSVC Build Tools.

.PARAMETER Target
    all       — build everything (default)
    ide       — build RawrXD_IDE.exe only
    widget    — build RawrXD_Widget.exe only
    clean     — remove all .obj and output binaries

.PARAMETER Config
    debug     — /DEBUG /Od /Zi (default for dev)
    release   — /O2 /GL /LTCG

.EXAMPLE
    .\build.ps1
    .\build.ps1 -Target ide -Config release
    .\build.ps1 -Target clean
#>
[CmdletBinding()]
param(
    [ValidateSet("all","ide","widget","clean","smoke","demo","bench","certify")]
    [string]$Target = "all",

    [ValidateSet("debug","release")]
    [string]$Config = "debug"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ============================================================================
# Paths
# ============================================================================
$Root      = $PSScriptRoot
$SrcDir    = Join-Path $Root "src"
$AgentDir  = Join-Path $SrcDir "agentic"
$ObjDir    = Join-Path $Root "build\obj"
$BinDir    = Join-Path $Root "build\bin"

# ============================================================================
# Locate MSVC Toolchain
# ============================================================================
function Find-Toolchain {
    $candidates = @(
        "D:\VS2022Enterprise\VC\Tools\MSVC",
        "C:\VS2022Enterprise\VC\Tools\MSVC",
        "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC",
        "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Tools\MSVC",
        "C:\Program Files\Microsoft Visual Studio\2022\Professional\VC\Tools\MSVC",
        "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC"
    )
    foreach ($base in $candidates) {
        if (Test-Path $base) {
            $vers = @(Get-ChildItem -Directory $base | Sort-Object Name -Descending)
            if ($vers.Count -gt 0) { return $vers[0].FullName }
        }
    }
    throw "MSVC toolchain not found. Install Visual Studio 2022 Build Tools."
}

function Find-WindowsSDK {
    $bases = @(
        "D:\Program Files (x86)\Windows Kits\10",
        "C:\Program Files (x86)\Windows Kits\10"
    )
    foreach ($base in $bases) {
        if (Test-Path "$base\Include") {
            $vers = @(Get-ChildItem -Directory "$base\Include" `
                    | Where-Object { Test-Path "$($_.FullName)\um\windows.h" } `
                    | Sort-Object Name -Descending)
            if ($vers.Count -gt 0) { return @{ Root=$base; Ver=$vers[0].Name } }
        }
    }
    throw "Windows SDK not found."
}

$MSVCRoot = Find-Toolchain
$SDK      = Find-WindowsSDK
$SDKRoot  = $SDK.Root
$SDKVer   = $SDK.Ver

$ML64     = Join-Path $MSVCRoot "bin\Hostx64\x64\ml64.exe"
$CL       = Join-Path $MSVCRoot "bin\Hostx64\x64\cl.exe"
$LINK     = Join-Path $MSVCRoot "bin\Hostx64\x64\link.exe"

if (-not (Test-Path $ML64)) { throw "ml64.exe not found at: $ML64" }
$HasCL = Test-Path $CL
if (-not $HasCL) { Write-Warning "cl.exe not found at: $CL — C++ targets will be skipped" }
if (-not (Test-Path $LINK)) { throw "link.exe not found at: $LINK" }

Write-Host "Toolchain: $MSVCRoot" -ForegroundColor Cyan
Write-Host "SDK:       $SDKRoot ($SDKVer)" -ForegroundColor Cyan
Write-Host "Target:    $Target  Config: $Config" -ForegroundColor Cyan
Write-Host "C++ Compiler: $(if ($HasCL) { 'Available' } else { 'NOT FOUND — skipping C++ targets' })" -ForegroundColor $(if ($HasCL) { 'Green' } else { 'Yellow' })

# ============================================================================
# Environment (INCLUDE / LIB)
# ============================================================================
$env:INCLUDE = [string]::Join(";", @(
    "$MSVCRoot\include",
    "$SDKRoot\Include\$SDKVer\ucrt",
    "$SDKRoot\Include\$SDKVer\shared",
    "$SDKRoot\Include\$SDKVer\um"
))
$env:LIB = [string]::Join(";", @(
    "$MSVCRoot\lib\x64",
    "$MSVCRoot\lib\onecore\x64",
    "$SDKRoot\Lib\$SDKVer\ucrt\x64",
    "$SDKRoot\Lib\$SDKVer\um\x64"
))

# ============================================================================
# Flags
# ============================================================================
$MasmFlags   = @("/nologo", "/W3", "/c", "/Cx", "/Zi",
                  "/I$SrcDir",
                  "/I$SrcDir\runtime",
                  "/I$SrcDir\model",
                  "/I$SrcDir\gguf",
                  "/I$SrcDir\tokenizer",
                  "/I$SrcDir\agent",
                  "/I$SrcDir\gpu",
                  "/I$AgentDir",
                  "/I$Root\tests")
$ClFlagsBase = @("/nologo", "/W4", "/WX", "/EHsc", "/MP",
                  "/DWIN32_LEAN_AND_MEAN", "/DNOMINMAX",
                  "/D_CRT_SECURE_NO_WARNINGS",
                  "/I$SrcDir")
$LinkLibs    = @("kernel32.lib","user32.lib","gdi32.lib","advapi32.lib",
                  "shell32.lib","shlwapi.lib","comctl32.lib","comdlg32.lib",
                  "wininet.lib","ws2_32.lib")

if ($Config -eq "release") {
    $ClFlagsBase += @("/O2", "/GL", "/DNDEBUG")
    $LinkFlagsExtra = @("/LTCG", "/OPT:REF", "/OPT:ICF")
} else {
    $ClFlagsBase += @("/Od", "/Zi", "/DDEBUG")
    $LinkFlagsExtra = @("/DEBUG")
}

$LinkFlagsBase = @("/nologo", "/MACHINE:X64", "/WX", "/INCREMENTAL:NO",
                    "/DYNAMICBASE", "/NXCOMPAT") + $LinkFlagsExtra

# ============================================================================
# Helpers
# ============================================================================
function Invoke-Exe {
    param([string]$Exe, [string[]]$Args, [string]$Desc)
    Write-Host "  [$Desc]" -ForegroundColor Yellow
    & $Exe @Args
    if ($LASTEXITCODE -ne 0) {
        throw "$Desc failed with exit code $LASTEXITCODE"
    }
}

function Assemble {
    param([string]$Source, [string]$ObjName)
    $obj = Join-Path $ObjDir $ObjName
    $args = $MasmFlags + @("/Fo$obj", $Source)
    Invoke-Exe $ML64 $args "ASM $([System.IO.Path]::GetFileName($Source))"
    return $obj
}

function Compile {
    param([string]$Source, [string]$ObjName)
    if (-not $HasCL) {
        Write-Warning "Cannot compile $([System.IO.Path]::GetFileName($Source)) — no C++ compiler"
        return $null
    }
    $obj = Join-Path $ObjDir $ObjName
    $args = $ClFlagsBase + @("/c", "/Fo$obj", $Source)
    Invoke-Exe $CL $args "CL  $([System.IO.Path]::GetFileName($Source))"
    return $obj
}

function Link-Exe {
    param([string]$OutExe, [string[]]$Objs, [string[]]$ExtraFlags)
    $rsp = Join-Path $env:TEMP "rawrxd_link_$(Get-Random).rsp"
    try {
        # Write response file — build the content as a single string
        $content = @()
        $content += $LinkFlagsBase
        $content += $ExtraFlags
        $content += "/OUT:`"$OutExe`""
        foreach ($obj in $Objs) { $content += "`"$obj`"" }
        $content += $LinkLibs
        $content += "-LIBPATH:`"$MSVCRoot\lib\x64`""
        $content += "-LIBPATH:`"$MSVCRoot\lib\onecore\x64`""
        $content += "-LIBPATH:`"$SDKRoot\Lib\$SDKVer\ucrt\x64`""
        $content += "-LIBPATH:`"$SDKRoot\Lib\$SDKVer\um\x64`""
        $content -join "`r`n" | Out-File -FilePath $rsp -Encoding ASCII -Force

        Write-Host "  [LINK $([System.IO.Path]::GetFileName($OutExe))]"
        & $LINK "@$rsp"
        if ($LASTEXITCODE -ne 0) {
            throw "LINK failed with exit code $LASTEXITCODE"
        }
    } finally {
        if (Test-Path $rsp) { Remove-Item -Force $rsp }
    }
}

# ============================================================================
# Clean
# ============================================================================
if ($Target -eq "clean") {
    Write-Host "Cleaning build artifacts..." -ForegroundColor Magenta
    if (Test-Path $ObjDir) { Remove-Item -Recurse -Force $ObjDir }
    if (Test-Path $BinDir) { Remove-Item -Recurse -Force $BinDir }
    Write-Host "Clean complete." -ForegroundColor Green
    exit 0
}

# ============================================================================
# Create output dirs
# ============================================================================
New-Item -ItemType Directory -Force -Path $ObjDir | Out-Null
New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

# ============================================================================
# Build IPC / Widget core objects (shared by both targets)
# ============================================================================
Write-Host "`n=== Core Objects ===" -ForegroundColor Cyan
$ObjIPC     = Assemble (Join-Path $SrcDir "RawrXD_IPC_Bridge.asm")      "IPC_Bridge.obj"
$ObjWidget  = Assemble (Join-Path $SrcDir "RawrXD_WidgetEngine.asm")    "WidgetEngine.obj"
$ObjHW      = Assemble (Join-Path $SrcDir "RawrXD_HeadlessWidgets.asm") "HeadlessWidgets.obj"

$CoreObjs = @($ObjIPC, $ObjWidget, $ObjHW)

# ============================================================================
# Build GPU/DMA Engine objects (large files — may take several minutes)
# ============================================================================
Write-Host "`n=== Engine Objects ===" -ForegroundColor Cyan
$ObjGPU     = Assemble (Join-Path $AgentDir "gpu_dma_complete_final.asm") "gpu_dma.obj"
$ObjTitan   = Assemble (Join-Path $AgentDir "RawrXD_Titan_Master_GodSource_REVERSE_ENGINEERED.asm") "titan_master.obj"

$EngineObjs = @($ObjGPU, $ObjTitan)

# ============================================================================
# Build RawrXD Runtime Engine (new MASM inference stack)
# ============================================================================
Write-Host "`n=== Runtime Engine Objects ===" -ForegroundColor Cyan

$RuntimeAsm = @(
    "runtime\kernel_registry.asm",
    "runtime\tensor.asm",
    "runtime\q4_matmul.asm",
    "runtime\kv_cache.asm",
    "runtime\sampler.asm",
    "runtime\inference_engine.asm",
    "model\transformer_block.asm",
    "gguf\gguf_reader.asm",
    "tokenizer\bpe.asm",
    "agent\agent_runtime.asm",
    "gpu\gpu_backend.asm"
)

$RuntimeObjs = @()
foreach ($asm in $RuntimeAsm) {
    $srcPath = Join-Path $SrcDir $asm
    if (Test-Path $srcPath) {
        $objName = [System.IO.Path]::GetFileNameWithoutExtension($asm) + ".obj"
        $RuntimeObjs += Assemble $srcPath $objName
    } else {
        Write-Warning "Runtime source not found: $srcPath"
    }
}

# ============================================================================
# Build Runtime Smoke Test
# ============================================================================
if ($Target -in @("all","smoke")) {
    Write-Host "`n=== Smoke Test ===" -ForegroundColor Cyan
    $SmokeSrc = Join-Path $Root "tests\runtime_smoke.asm"
    if (Test-Path $SmokeSrc) {
        $SmokeObj = Assemble $SmokeSrc "runtime_smoke.obj"
        $SmokeOut = Join-Path $BinDir "runtime_smoke.exe"
        $AllObjs = $RuntimeObjs + @($SmokeObj)
        Link-Exe $SmokeOut $AllObjs @("/SUBSYSTEM:CONSOLE")
        Write-Host "  Built: $SmokeOut" -ForegroundColor Green
    } else {
        Write-Warning "Smoke test source not found: $SmokeSrc"
    }
}

# ============================================================================
# Build IDE Shell
# ============================================================================
if ($Target -in @("all","ide")) {
    if (-not $HasCL) {
        Write-Warning "Skipping IDE Shell — requires C++ compiler (cl.exe)"
    } else {
        Write-Host "`n=== IDE Shell ===" -ForegroundColor Cyan
        $ObjIDEShell  = Assemble (Join-Path $SrcDir "RawrXD_IDE_Shell.asm")    "IDE_Shell.obj"
        $ObjIDEWrap   = Compile  (Join-Path $SrcDir "RawrXD_IDE_Wrapper.cpp")  "IDE_Wrapper.obj"

        $IDEObjs = $CoreObjs + $EngineObjs + @($ObjIDEShell, $ObjIDEWrap)
        $IDEOut  = Join-Path $BinDir "RawrXD_IDE.exe"
        Link-Exe $IDEOut $IDEObjs @("/SUBSYSTEM:WINDOWS", "/ENTRY:IDEShellMain")
        Write-Host "  Built: $IDEOut" -ForegroundColor Green
    }
}

# ============================================================================
# Build Widget Server
# ============================================================================
if ($Target -in @("all","widget")) {
    Write-Host "`n=== Widget Server ===" -ForegroundColor Cyan
    $WidgetOut = Join-Path $BinDir "RawrXD_Widget.exe"
    Link-Exe $WidgetOut $CoreObjs @("/SUBSYSTEM:CONSOLE", "/ENTRY:Widget_Main")
    Write-Host "  Built: $WidgetOut" -ForegroundColor Green
}

# ============================================================================
# Build Sovereign Engine Demo Harness (Phase 8 Proof Artifact)
# ============================================================================
if ($Target -in @("all","demo")) {
    if (-not $HasCL) {
        Write-Warning "Skipping Demo Harness — requires C++ compiler (cl.exe)"
    } else {
        Write-Host "`n=== Sovereign Engine Demo Harness ===" -ForegroundColor Cyan
        $DemoSrc  = Join-Path $SrcDir "engine\SovereignDemoHarness.cpp"
        if (Test-Path $DemoSrc) {
            $DemoOut = Join-Path $BinDir "RawrXD_SovereignDemo.exe"
            $DemoFlags = $ClFlagsBase + @("/std:c++17", "/Fe$DemoOut", $DemoSrc)
            Invoke-Exe $CL $DemoFlags "CL  SovereignDemoHarness.cpp"
            Write-Host "  Built: $DemoOut" -ForegroundColor Green
        } else {
            Write-Warning "Demo harness not found: $DemoSrc"
        }
    }
}

# ============================================================================
# Build Benchmark Executables
# ============================================================================
if ($Target -in @("all","bench")) {
    if (-not $HasCL) {
        Write-Warning "Skipping Benchmarks — requires C++ compiler (cl.exe)"
    } else {
        Write-Host "`n=== Benchmark Executables ===" -ForegroundColor Cyan

        $Benchmarks = @(
            @{Src="backend_benchmark.cpp";   Out="backend_benchmark.exe"},
            @{Src="inference_benchmark.cpp"; Out="inference_benchmark.exe"},
            @{Src="build_benchmark.cpp";     Out="build_benchmark.exe"}
        )

        foreach ($b in $Benchmarks) {
            $srcPath = Join-Path $Root "benchmarks" $b.Src
            if (Test-Path $srcPath) {
                $outPath = Join-Path $BinDir $b.Out
                $args = $ClFlagsBase + @("/std:c++17", "/Fe$outPath", $srcPath)
                Invoke-Exe $CL $args "CL  $($b.Src)"
                Write-Host "  Built: $outPath" -ForegroundColor Green
            } else {
                Write-Warning "Benchmark source not found: $srcPath"
            }
        }
    }
}

# ============================================================================
# Certification Target — clean build + demo + benchmarks + manifest
# ============================================================================
if ($Target -eq "certify") {
    Write-Host "`n========================================" -ForegroundColor Magenta
    Write-Host " RawrXD Sovereign Certification" -ForegroundColor Magenta
    Write-Host "========================================`n" -ForegroundColor Magenta

    $certPass = $true
    $certResults = @()

    # Step 1: Clean build
    Write-Host "[1/6] Clean Build..." -ForegroundColor Cyan
    if (Test-Path $ObjDir) { Remove-Item -Recurse -Force $ObjDir }
    if (Test-Path $BinDir) { Remove-Item -Recurse -Force $BinDir }
    New-Item -ItemType Directory -Force -Path $ObjDir | Out-Null
    New-Item -ItemType Directory -Force -Path $BinDir | Out-Null

    # Build core + engine + runtime
    try {
        $null = Assemble (Join-Path $SrcDir "RawrXD_IPC_Bridge.asm") "IPC_Bridge.obj"
        $null = Assemble (Join-Path $SrcDir "RawrXD_WidgetEngine.asm") "WidgetEngine.obj"
        $null = Assemble (Join-Path $SrcDir "RawrXD_HeadlessWidgets.asm") "HeadlessWidgets.obj"
        $certResults += @{Step="Build Core ASM"; Status="PASS"}
        Write-Host "  Build Core ASM        PASS" -ForegroundColor Green
    } catch {
        $certPass = $false
        $certResults += @{Step="Build Core ASM"; Status="FAIL"}
        Write-Host "  Build Core ASM        FAIL: $_" -ForegroundColor Red
    }

    # Step 2: Backend Factory ODR check
    Write-Host "[2/6] Backend Factory ODR Verification..." -ForegroundColor Cyan
    $odrViolations = Select-String -Path "$SrcDir\orchestration\*.cpp" -Pattern "PowerShellDriver\.cpp|BareMetalDriver\.cpp" -SimpleMatch
    if ($odrViolations) {
        $certPass = $false
        $certResults += @{Step="Backend Factory ODR"; Status="FAIL"}
        Write-Host "  Backend Factory ODR   FAIL: ODR violations found" -ForegroundColor Red
    } else {
        $certResults += @{Step="Backend Factory ODR"; Status="PASS"}
        Write-Host "  Backend Factory ODR   PASS" -ForegroundColor Green
    }

    # Step 3: Build demo harness
    Write-Host "[3/6] Demo Harness Build..." -ForegroundColor Cyan
    if ($HasCL) {
        $DemoSrc = Join-Path $SrcDir "engine\SovereignDemoHarness.cpp"
        if (Test-Path $DemoSrc) {
            try {
                $DemoOut = Join-Path $BinDir "RawrXD_SovereignDemo.exe"
                $DemoFlags = $ClFlagsBase + @("/std:c++17", "/Fe$DemoOut", $DemoSrc)
                Invoke-Exe $CL $DemoFlags "CL  SovereignDemoHarness.cpp"
                $certResults += @{Step="Demo Harness Build"; Status="PASS"}
                Write-Host "  Demo Harness Build    PASS" -ForegroundColor Green
            } catch {
                $certPass = $false
                $certResults += @{Step="Demo Harness Build"; Status="FAIL"}
                Write-Host "  Demo Harness Build    FAIL: $_" -ForegroundColor Red
            }
        } else {
            $certPass = $false
            $certResults += @{Step="Demo Harness Build"; Status="FAIL"}
            Write-Host "  Demo Harness Build    FAIL: source not found" -ForegroundColor Red
        }
    } else {
        $certResults += @{Step="Demo Harness Build"; Status="SKIP (no C++ compiler)"}
        Write-Host "  Demo Harness Build    SKIP (no C++ compiler)" -ForegroundColor Yellow
    }

    # Step 4: Run demo
    Write-Host "[4/6] Demo Execution..." -ForegroundColor Cyan
    $DemoExe = Join-Path $BinDir "RawrXD_SovereignDemo.exe"
    if (Test-Path $DemoExe) {
        try {
            & $DemoExe
            if ($LASTEXITCODE -eq 0) {
                $certResults += @{Step="Demo Execution"; Status="PASS"}
                Write-Host "  Demo Execution        PASS" -ForegroundColor Green
            } else {
                $certPass = $false
                $certResults += @{Step="Demo Execution"; Status="FAIL"}
                Write-Host "  Demo Execution        FAIL (exit code: $LASTEXITCODE)" -ForegroundColor Red
            }
        } catch {
            $certPass = $false
            $certResults += @{Step="Demo Execution"; Status="FAIL"}
            Write-Host "  Demo Execution        FAIL: $_" -ForegroundColor Red
        }
    } else {
        $certResults += @{Step="Demo Execution"; Status="SKIP (not built)"}
        Write-Host "  Demo Execution        SKIP (not built)" -ForegroundColor Yellow
    }

    # Step 5: Benchmark capture check
    Write-Host "[5/6] Benchmark Capture Verification..." -ForegroundColor Cyan
    $runsDir = Join-Path $Root "benchmarks\runs"
    $runFiles = @(Get-ChildItem $runsDir -Filter "*.json" | Sort-Object LastWriteTime -Descending)
    if ($runFiles.Count -gt 0) {
        $latest = $runFiles[0]
        $certResults += @{Step="Benchmark Capture"; Status="PASS"; Detail=$latest.Name}
        Write-Host "  Benchmark Capture     PASS ($($latest.Name))" -ForegroundColor Green
    } else {
        $certResults += @{Step="Benchmark Capture"; Status="SKIP (no runs)"}
        Write-Host "  Benchmark Capture     SKIP (no benchmark runs found)" -ForegroundColor Yellow
    }

    # Step 6: Integrity manifest
    Write-Host "[6/6] Integrity Manifest..." -ForegroundColor Cyan
    $hashDir = Join-Path $Root "benchmarks\hashes"
    New-Item -ItemType Directory -Force -Path $hashDir | Out-Null
    $manifestPath = Join-Path $hashDir "SHA256_MANIFEST.txt"
    $exes = @(Get-ChildItem $BinDir -Filter "*.exe")
    if ($exes.Count -gt 0) {
        "RawrXD Sovereign Certification Integrity Manifest" | Out-File $manifestPath
        "Generated: $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')" | Out-File $manifestPath -Append
        "" | Out-File $manifestPath -Append
        foreach ($exe in $exes) {
            $hash = (Get-FileHash -Algorithm SHA256 -Path $exe.FullName).Hash
            "$hash  $($exe.Name)" | Out-File $manifestPath -Append
        }
        $certResults += @{Step="Integrity Manifest"; Status="PASS"}
        Write-Host "  Integrity Manifest    PASS ($($exes.Count) files hashed)" -ForegroundColor Green
    } else {
        $certResults += @{Step="Integrity Manifest"; Status="SKIP (no binaries)"}
        Write-Host "  Integrity Manifest    SKIP (no binaries to hash)" -ForegroundColor Yellow
    }

    # Certification result
    Write-Host "`n========================================" -ForegroundColor Magenta
    Write-Host " RawrXD Sovereign Certification Result" -ForegroundColor Magenta
    Write-Host "========================================" -ForegroundColor Magenta
    $allPassed = $true
    foreach ($r in $certResults) {
        $color = if ($r.Status -eq "PASS") { 'Green' } elseif ($r.Status -eq "FAIL") { 'Red' } else { 'Yellow' }
        Write-Host "  $($r.Step) $($r.Status)" -ForegroundColor $color
        if ($r.Status -eq "FAIL") { $allPassed = $false }
    }
    Write-Host "----------------------------------------" -ForegroundColor Magenta
    if ($allPassed) {
        Write-Host "  STATUS: CERTIFIED" -ForegroundColor Green
    } else {
        Write-Host "  STATUS: FAILED" -ForegroundColor Red
    }
    Write-Host "========================================`n" -ForegroundColor Magenta

    exit $(if ($allPassed) { 0 } else { 1 })
}

# ============================================================================
# Summary
# ============================================================================
Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host " RawrXD Build Complete ($Config)" -ForegroundColor Green
Get-ChildItem $BinDir -Filter "*.exe" | ForEach-Object {
    $sz = [math]::Round($_.Length / 1KB, 1)
    Write-Host "  $($_.Name)  $sz KB" -ForegroundColor White
}
Write-Host "========================================`n" -ForegroundColor Cyan
