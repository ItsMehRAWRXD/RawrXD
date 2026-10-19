$ErrorActionPreference='Continue'
Start-Transcript -Path 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_002\transcript.txt' -Force
try {
  & 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_002\run_r1_matrix.ps1'
  Write-Output "SCRIPT_EC=$LASTEXITCODE"
} catch {
  Write-Output "BOOT_CATCH=$($_.Exception.Message)"
  $_ | Format-List * -Force
} finally {
  Stop-Transcript
}