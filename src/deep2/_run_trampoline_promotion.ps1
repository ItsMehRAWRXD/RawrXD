$ErrorActionPreference = 'Continue'
$src = 'G:\~dev\rawrxd'
$b = 'G:\~dev\rawrxd\build_fused_control'
# Skip full reconfigure unless needed — rebuild target only
cmake --build $b --target deep2_k2_full_depth_trampoline_promotion_cert -j 8
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$env:DEEP2_EFF_TOKENS = '2'
$env:DEEP2_EFF_LAYER_DEPTH = '61'
Write-Output '=== RUN K2_FULL_DEPTH_TRAMPOLINE_PROMOTION_001 ==='
& "$b\bin\deep2_k2_full_depth_trampoline_promotion_cert.exe"
Write-Output "exit=$LASTEXITCODE"
exit $LASTEXITCODE
