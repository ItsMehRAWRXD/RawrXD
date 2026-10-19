$ErrorActionPreference = "Continue"
$ev = "G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_002"
# Stop ollama again
Get-Process ollama* -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
# Run full matrix fresh - more reliable than resume surgery
& "$ev\run_r1_matrix.ps1"
exit $LASTEXITCODE
