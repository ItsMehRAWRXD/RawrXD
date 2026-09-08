$ErrorActionPreference = "Stop"

$Repo = "G:\~dev\rawrxd"
$Build = Join-Path $Repo "build-ninja"

Set-Location $Build
ninja deep2_vwa_core_poc_001
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

.\bin\deep2_vwa_core_poc_001.exe 2>&1 |
    Tee-Object -FilePath (Join-Path $Repo "evidence\VWA_CORE_POC_001\RUN_LOG.txt")
