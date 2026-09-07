$ErrorActionPreference = 'Continue'
$exe = 'G:\~dev\rawrxd\build_fused_control\bin\deep2_live_path_fused_control_cert.exe'
$env:DEEP2_EFF_TOKENS = '4'
$env:DEEP2_EFF_LAYER_DEPTH = '4'
Write-Output "Running $exe"
& $exe
Write-Output "exit=$LASTEXITCODE"
