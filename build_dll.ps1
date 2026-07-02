# ==============================================================================
# build_dll.ps1 — Produce sovereign.dll + sovereign.lib from MASM objects
# ==============================================================================
# Usage: .\build_dll.ps1
# Output: d:\rawrxd-ci-bootstrap\bin\sovereign.dll
#         d:\rawrxd-ci-bootstrap\bin\sovereign.lib
# ==============================================================================

param(
    [string]$SrcDir = "d:\rawrxd-ci-bootstrap",
    [string]$OutDir = "d:\rawrxd-ci-bootstrap\bin"
)

$ErrorActionPreference = "Stop"

# Find ML64
$ML64 = $null
$PossiblePaths = @(
    "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\ml64.exe",
    "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe",
    "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe"
)
foreach ($path in $PossiblePaths) {
    if (Test-Path $path) { $ML64 = $path; break }
}
if (-not $ML64) { Write-Error "ml64.exe not found"; exit 1 }

# Find LINK
$LINK = (Join-Path (Split-Path $ML64) "link.exe")
if (-not (Test-Path $LINK)) { Write-Error "link.exe not found"; exit 1 }

Write-Host "Found ML64: $ML64" -ForegroundColor Green
Write-Host "Found LINK: $LINK" -ForegroundColor Green

# Ensure output directory
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir -Force | Out-Null }

# Assemble all components that contribute to the DLL
# NOTE: Order matters for deterministic linking. All listed sources must exist.
$Components = @(
    @{Name="Ghost Engine";          Asm="Sovereign_Ghost_Engine.asm";         Obj="Sovereign_Ghost_Engine.obj"},
    @{Name="Model Streamer";        Asm="Sovereign_Model_Streamer.asm";       Obj="Sovereign_Model_Streamer.obj"},
    @{Name="Hook Simulator";        Asm="Sovereign_Hook_Simulator.asm";       Obj="Sovereign_Hook_Simulator.obj"},
    @{Name="Symbolic Validator";    Asm="Sovereign_Symbolic_Validator.asm";   Obj="Sovereign_Symbolic_Validator.obj"},
    @{Name="Unified Entry";         Asm="Sovereign_Unified_Entry.asm";        Obj="Sovereign_Unified_Entry.obj"},
    @{Name="Dynamic Controller";    Asm="Sovereign_Dynamic_Ctrl.asm";         Obj="Sovereign_Dynamic_Ctrl.obj"},
    @{Name="Core Engine";           Asm="Sovereign_Core_Engine.asm";          Obj="Sovereign_Core_Engine.obj"},
    @{Name="Hypervisor Init";       Asm="Sovereign_Hyper_Init.asm";           Obj="Sovereign_Hyper_Init.obj"},
    @{Name="AI Orchestrator";       Asm="Sovereign_AI_Orchestrator.asm";      Obj="Sovereign_AI_Orchestrator.obj"},
    @{Name="GGUF Loader";           Asm="Sovereign_GGUF_Loader.asm";          Obj="Sovereign_GGUF_Loader.obj"},
    @{Name="Sovereign Switch";      Asm="Sovereign_Switch.asm";               Obj="Sovereign_Switch.obj"}
    # NOTE: Telemetry API symbols (PIN_THREAD, READ_LATENCY, WRITE_LATENCY)
    # are already provided by Sovereign_Unified_Entry.asm. Do not add
    # Sovereign_Telemetry_API.asm here to avoid duplicate symbol errors.
)

$SuccessCount = 0
foreach ($comp in $Components) {
    $asmPath = Join-Path $SrcDir $comp.Asm
    $objPath = Join-Path $OutDir $comp.Obj
    if (-not (Test-Path $asmPath)) {
        Write-Host "  [!] Skipping $($comp.Name) — source not found" -ForegroundColor Yellow
        continue
    }
    Write-Host "  Assembling $($comp.Name)..." -NoNewline
    & $ML64 /c /W3 /nologo /Zi /Fo $objPath $asmPath 1>$null 2>$null
    if ($LASTEXITCODE -eq 0) {
        Write-Host " OK" -ForegroundColor Green
        $SuccessCount++
    } else {
        Write-Host " FAILED" -ForegroundColor Red
    }
}
Write-Host "Assembly: $SuccessCount/$($Components.Count) succeeded" -ForegroundColor Cyan

# Collect explicit object files from components + C wrapper
$ObjFiles = @()
foreach ($comp in $Components) {
    $objPath = Join-Path $OutDir $comp.Obj
    if (Test-Path $objPath) {
        $ObjFiles += $objPath
    } else {
        Write-Error "Missing required object: $objPath"
        exit 1
    }
}
# C wrapper
$WrapperObj = Join-Path $OutDir "sovereign_wrapper.obj"
if (Test-Path $WrapperObj) {
    $ObjFiles += $WrapperObj
} else {
    Write-Error "Missing required object: $WrapperObj"
    exit 1
}

# Link DLL
Write-Host "Linking sovereign.dll..." -NoNewline
$libDir = "C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64"
$defPath = Join-Path $SrcDir "sovereign.def"
$dllOut  = Join-Path $OutDir "sovereign.dll"

& $LINK /NOLOGO /DLL /DEF:$defPath `
    /SUBSYSTEM:WINDOWS /NODEFAULTLIB /ENTRY:DllMain /FIXED /BASE:0x10000000 `
    /OUT:$dllOut `
    $ObjFiles `
    (Join-Path $libDir "kernel32.lib") `
    (Join-Path $libDir "user32.lib") `
    (Join-Path $libDir "gdi32.lib") `
    1>(Join-Path $OutDir "link_dll_out.log") `
    2>(Join-Path $OutDir "link_dll_err.log")

if ($LASTEXITCODE -ne 0) {
    Write-Host " FAILED" -ForegroundColor Red
    $errLog = Join-Path $OutDir "link_dll_err.log"
    if (Test-Path $errLog) { Get-Content $errLog | Write-Host -ForegroundColor DarkRed }
    exit 1
}

Write-Host " OK" -ForegroundColor Green
$dllPath = Join-Path $OutDir "sovereign.dll"
$libPath = Join-Path $OutDir "sovereign.lib"
$dllSize = (Get-Item $dllPath).Length
Write-Host "  DLL: $dllPath ($dllSize bytes)" -ForegroundColor Green
if (Test-Path $libPath) {
    $libSize = (Get-Item $libPath).Length
    Write-Host "  LIB: $libPath ($libSize bytes)" -ForegroundColor Green
}

# --- Export verification gate ---
Write-Host "Verifying exports..." -NoNewline
$RequiredExports = @(
    "SovereignLoadModel","SovereignUnloadModel","SovereignIsModelReady",
    "SovereignGetModelInfo","SovereignGetTensorCount","SovereignGetTensorByIndex",
    "SovereignGetTensorOffset"
)
$dump = & "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\dumpbin.exe" /EXPORTS $dllPath 2>$null
$missing = @()
foreach ($exp in $RequiredExports) {
    if (-not ($dump -match "\b$exp\b")) { $missing += $exp }
}
if ($missing.Count -gt 0) {
    Write-Host " FAIL" -ForegroundColor Red
    Write-Host "Missing exports: $($missing -join ', ')" -ForegroundColor DarkRed
    exit 1
}
Write-Host " OK" -ForegroundColor Green

Write-Host "Done." -ForegroundColor Cyan
