# verify_rawr_after_reboot.ps1 — RAWRXD_REBOOT_PERSISTENCE_AUTHORITY_001
# Run this after reboot to prove fresh OS shell resolves rawr + model dir persists.
$receipt = "F:\~dev\_rawr_reboot_persistence_receipt.txt"

$rawr = (Get-Command rawr -ErrorAction SilentlyContinue).Source
$ide = (Get-Command RawrXD-Win32IDE -ErrorAction SilentlyContinue).Source

$modelDirUser = [Environment]::GetEnvironmentVariable("RAWRXD_MODEL_DIR", "User")
$modelDirMachine = [Environment]::GetEnvironmentVariable("RAWRXD_MODEL_DIR", "Machine")
$modelDir = if ($modelDirUser) { $modelDirUser } else { $modelDirMachine }

$dumpOut = "F:\~dev\_post_reboot_rawr_dump.txt"
$runOut = "F:\~dev\_post_reboot_rawr_run_stdout.txt"
$runErr = "F:\~dev\_post_reboot_rawr_run_stderr.txt"

$dumpExit = 999
$runExit = 999

if ($rawr) {
    & $rawr dump --format receipt > $dumpOut 2>&1
    $dumpExit = $LASTEXITCODE

    & $rawr run --tokens 3 F:\~dev\qwen2.5-coder-1.5b-base.gguf "hello" > $runOut 2> $runErr
    $runExit = $LASTEXITCODE
}

$dumpPass = [int]((Test-Path $dumpOut) -and ((Select-String -Path $dumpOut -Pattern "VERDICT=PASS" -ErrorAction SilentlyContinue).Count -gt 0))
$runGenerated = [int]((Test-Path $runErr) -and ((Select-String -Path $runErr -Pattern "GENERATED_TOKEN_COUNT|tokens|TPS|COMPLETED" -ErrorAction SilentlyContinue).Count -gt 0))

$pass = (
    $rawr -and
    $modelDir -and
    (Test-Path $modelDir) -and
    $dumpExit -eq 0 -and
    $dumpPass -eq 1 -and
    $runExit -eq 0
)

$verdict = if ($pass) { 'PASS' } else { 'FAIL' }

@(
  "RAWRXD_REBOOT_PERSISTENCE_AUTHORITY_001=ENTERED"
  "AUTOSTART_POLICY=CLI_ONLY_NO_AUTOSTART"
  "FRESH_OS_SHELL_RAWR_PATH=$rawr"
  "FRESH_OS_SHELL_IDE_PATH=$ide"
  "PATH_RESOLVES_RAWR=$([int]($rawr -ne $null -and $rawr -ne ''))"
  "RAWRXD_MODEL_DIR_USER=$modelDirUser"
  "RAWRXD_MODEL_DIR_MACHINE=$modelDirMachine"
  "RAWRXD_MODEL_DIR_EFFECTIVE=$modelDir"
  "MODEL_DIR_EXISTS=$([int]($modelDir -and (Test-Path $modelDir)))"
  "RAWR_DUMP_EXIT=$dumpExit"
  "RAWR_DUMP_RECEIPT_HAS_PASS=$dumpPass"
  "RAWR_RUN_EXIT=$runExit"
  "RAWR_RUN_GENERATION_OBSERVED=$runGenerated"
  "VERDICT=$verdict"
) | Set-Content $receipt -Encoding UTF8

Get-Content $receipt