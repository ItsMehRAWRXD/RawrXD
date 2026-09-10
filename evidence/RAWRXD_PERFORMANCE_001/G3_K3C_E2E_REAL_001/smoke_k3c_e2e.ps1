# G3_K3C_E2E_REAL_001 — build+run via build-fd (PROMOTE=0)
$ErrorActionPreference = "Stop"
$root = "G:\~dev\rawrxd"
$bd = "$root\build-fd"
$ev = "$root\evidence\RAWRXD_PERFORMANCE_001\G3_K3C_E2E_REAL_001"
$model = "$root\models\tinyllama.gguf"
$exe = "$bd\bin\smoke_k3c_e2e.exe"

cmake --build $bd --target smoke_k3c_e2e --config Release
if ($LASTEXITCODE -ne 0) {
  "SMOKE_COMPILE=FAIL" | Set-Content (Join-Path $ev "SMOKE_OUT.txt")
  exit $LASTEXITCODE
}
"SMOKE_COMPILE=PASS" | Set-Content (Join-Path $ev "SMOKE_OUT.txt")

$env:RAWRXD_HOST_DECODE = "0"
& $exe $model 2>&1 | Tee-Object -FilePath (Join-Path $ev "SMOKE_OUT.txt") -Append
exit $LASTEXITCODE
