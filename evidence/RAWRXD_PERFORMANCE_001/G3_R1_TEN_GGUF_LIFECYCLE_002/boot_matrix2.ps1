$ErrorActionPreference='Continue'
Start-Transcript -Path 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_002\transcript2.txt' -Force
& 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_R1_TEN_GGUF_LIFECYCLE_002\run_r1_matrix.ps1'
Write-Host "SCRIPT_EC=$LASTEXITCODE"
Stop-Transcript