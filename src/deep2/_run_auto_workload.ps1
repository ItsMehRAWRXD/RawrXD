$ErrorActionPreference = 'Continue'
$b = 'G:\~dev\rawrxd\build_fused_control'
cmake --build $b --target deep2_k2_auto_workload_policy_cert -j 8
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$env:DEEP2_EFF_TOKENS = '2'
$env:DEEP2_EFF_LAYER_DEPTH = '61'
Write-Output '=== RUN K2_AUTO_WORKLOAD_POLICY_001 ==='
& "$b\bin\deep2_k2_auto_workload_policy_cert.exe"
Write-Output "exit=$LASTEXITCODE"
exit $LASTEXITCODE
