# D04 GATE Certification Environment Setup
# Phase 1: Authoritative Baseline

# Set all required environment variables
$env:DEEP2_REQUIRE_REFERENCE_PAIR = "0"
$env:RAWRXD_GPU_FWD = "1"
$env:DEEP2_DISABLE_VULKAN = "0"
$env:DEEP2_RESIDENT_FIRST = "1"
$env:DEEP2_D04_BATCH_WIDTH = "0"

Write-Host "D04 Environment Variables Set:"
Write-Host "  DEEP2_REQUIRE_REFERENCE_PAIR=$env:DEEP2_REQUIRE_REFERENCE_PAIR"
Write-Host "  RAWRXD_GPU_FWD=$env:RAWRXD_GPU_FWD"
Write-Host "  DEEP2_DISABLE_VULKAN=$env:DEEP2_DISABLE_VULKAN"
Write-Host "  DEEP2_RESIDENT_FIRST=$env:DEEP2_RESIDENT_FIRST"
Write-Host "  DEEP2_D04_BATCH_WIDTH=$env:DEEP2_D04_BATCH_WIDTH"

# Verify files exist
$exe = "F:\~dev\build_streaming\Release\deep2_185in30_gate.exe"
$model = "F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf"

Write-Host ""
Write-Host "File Checks:"
Write-Host "  Executable: $(Test-Path $exe)"
Write-Host "  Model: $(Test-Path $model)"

if (-not (Test-Path $exe)) {
    Write-Host "ERROR: Executable not found at $exe"
    exit 1
}
if (-not (Test-Path $model)) {
    Write-Host "ERROR: Model not found at $model"
    exit 1
}

Write-Host ""
Write-Host "Ready to run baseline. Press Enter to continue or Ctrl+C to abort..."
$null = $host.UI.RawReadKey("NoEcho,IncludeKeyDown")