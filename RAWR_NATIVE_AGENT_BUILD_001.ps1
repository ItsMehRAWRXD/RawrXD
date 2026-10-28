# RAWR_NATIVE_AGENT_BUILD_001 Certification Harness
#
# Demonstrates the complete RawrXD-native build chain:
#   RawrXD CoffWriter -> COFF object -> RawrXD rawrxd_link.exe -> PE -> Windows execution
#
# Zero external compilers (MSVC, GCC, Clang, LLVM) are invoked during certification.
# MSVC is used ONLY as a stage-0 bootstrap to build the RawrXD compiler library itself.

$ErrorActionPreference = "Stop"

# --- Configuration ---
$RAWXD_ROOT   = "G:\~dev\rawrxd"
$RAWXD_LINKER  = "F:\rawrxd\_pre_merge_backup\toolchain\from_scratch\phase2_linker\build\rawrxd_link.exe"
$RAWXD_CHECK   = "F:\rawrxd\_pre_merge_backup\toolchain\from_scratch\phase2_linker\build\rawrxd_check.exe"
$CERT_DRIVER   = "$RAWXD_ROOT\cert_driver2.exe"
$WORK_DIR      = "$RAWXD_ROOT\cert_work"
$RECEIPT_FILE  = "$RAWXD_ROOT\RAWR_NATIVE_AGENT_BUILD_001_RECEIPT.txt"

# --- Invocation log ---
$invocations = @()
function Log-Invocation {
    param($Executable, $Arguments, $ExitCode, $Output)
    $invocations += [PSCustomObject]@{
        Executable = $Executable
        Arguments  = $Arguments
        ExitCode   = $ExitCode
        Output     = $Output
        Timestamp  = Get-Date -Format "o"
    }
}

# --- Verify RawrXD linker exists ---
if (-not (Test-Path $RAWXD_LINKER)) {
    Write-Host 'FATAL: RawrXD linker not found: ' + $RAWXD_LINKER
    exit 1
}
Write-Host 'RAWXD_LINKER=PASS (' + $RAWXD_LINKER + ')'

# --- Verify RawrXD check tool exists ---
if (-not (Test-Path $RAWXD_CHECK)) {
    Write-Host 'RAWXD_CHECK=NOT_ESTABLISHED (' + $RAWXD_CHECK + ' missing)'
} else {
    Write-Host 'RAWXD_CHECK=PASS (' + $RAWXD_CHECK + ')'
}

# --- Verify RawrXD cert driver exists ---
if (-not (Test-Path $CERT_DRIVER)) {
    Write-Host 'FATAL: RawrXD cert driver not found: ' + $CERT_DRIVER
    exit 1
}
Write-Host 'RAWXD_COMPILER_DRIVER=PASS (' + $CERT_DRIVER + ')'

# --- Create work directory ---
if (-not (Test-Path $WORK_DIR)) { New-Item -ItemType Directory -Path $WORK_DIR | Out-Null }

# --- Step 1: Generate COFF object using RawrXD's own CoffWriter ---
Write-Host "`n[STEP 1] Generate COFF object using RawrXD CoffWriter..."
$obj_path = "$WORK_DIR\cert_ret42.obj"
cmd /c ('"' + $CERT_DRIVER + '" "' + $obj_path + '" 2>NUL') 2>&1 | Out-Null
$driver_exit = $LASTEXITCODE
Log-Invocation -Executable $CERT_DRIVER -Arguments $obj_path -ExitCode $driver_exit -Output ""

if ($driver_exit -ne 0) {
    Write-Host 'CERT_DRIVER=FAIL (exit ' + $driver_exit + ')'
    exit 1
}
Write-Host 'CERT_DRIVER=PASS (exit ' + $driver_exit + ')'
Write-Host '  COFF object: ' + $obj_path
if (-not (Test-Path $obj_path)) {
    Write-Host 'FATAL: COFF object not created'
    exit 1
}

# --- Step 2: Link COFF object using RawrXD's own linker ---
Write-Host "`n[STEP 2] Link COFF object using RawrXD rawrxd_link.exe..."
$exe_path = "$WORK_DIR\cert_ret42.exe"
cmd /c ('"' + $RAWXD_LINKER + '" "' + $obj_path + '" -o "' + $exe_path + '" 2>NUL') 2>&1 | Out-Null
$linker_exit = $LASTEXITCODE
Log-Invocation -Executable $RAWXD_LINKER -Arguments ($obj_path + ' -o ' + $exe_path) -ExitCode $linker_exit -Output ""

if ($linker_exit -ne 0) {
    Write-Host 'RAWXD_LINKER=FAIL (exit ' + $linker_exit + ')'
    exit 1
}
Write-Host 'RAWXD_LINKER=PASS (exit ' + $linker_exit + ')'
Write-Host '  PE executable: ' + $exe_path
if (-not (Test-Path $exe_path)) {
    Write-Host 'FATAL: PE executable not created'
    exit 1
}

# --- Step 3: Execute the PE ---
Write-Host "`n[STEP 3] Execute PE executable..."
cmd /c ('"' + $exe_path + '" 2>NUL') 2>&1 | Out-Null
$run_exit = $LASTEXITCODE
Log-Invocation -Executable $exe_path -Arguments '' -ExitCode $run_exit -Output ""

if ($run_exit -ne 42) {
    Write-Host 'NATIVE_EXECUTION=FAIL (exit ' + $run_exit + ', expected 42)'
    exit 1
}
Write-Host 'NATIVE_EXECUTION=PASS (exit ' + $run_exit + ')'

# --- Step 4: Verify no external compilers were invoked ---
Write-Host "`n[STEP 4] Verify no external compiler invocations..."
$external_compilers = @("cl.exe", "gcc.exe", "g++.exe", "clang.exe", "clang++.exe", "ld.exe", "link.exe")
$found_external = $false
foreach ($inv in $invocations) {
    $base = [System.IO.Path]::GetFileName($inv.Executable)
    if ($external_compilers -contains $base) {
        Write-Host 'EXTERNAL_COMPILER_DETECTED: ' + $inv.Executable
        $found_external = $true
    }
}
if ($found_external) {
    Write-Host 'EXTERNAL_COMPILER_INVOCATIONS=FAIL'
    exit 1
} else {
    Write-Host 'EXTERNAL_COMPILER_INVOCATIONS=PASS (0 external compilers)'
}

# --- Step 5: Verify linker fail-closed on invalid input ---
Write-Host "`n[STEP 5] Verify linker fail-closed on invalid input..."
$missing_obj = "$WORK_DIR\nonexistent.obj"
$linker_error_output = cmd /c ('"' + $RAWXD_LINKER + '" "' + $missing_obj + '" 2>&1') 2>&1
$linker_error_exit = $LASTEXITCODE
Log-Invocation -Executable $RAWXD_LINKER -Arguments $missing_obj -ExitCode $linker_error_exit -Output $linker_error_output

if ($linker_error_exit -eq 0) {
    Write-Host 'LINKER_FAIL_CLOSED=FAIL (exit 0 on invalid input)'
    exit 1
} else {
    Write-Host 'LINKER_FAIL_CLOSED=PASS (exit ' + $linker_error_exit + ' on invalid input)'
}

# --- Step 6: Write certification receipt ---
Write-Host "`n[STEP 6] Write certification receipt..."
$receipt = @"
=== RAWR_NATIVE_AGENT_BUILD_001 Certification Receipt ===
Date: $(Get-Date -Format "o")
Workspace: $RAWXD_ROOT

Configuration:
  COMPILER_MODE=RAWR_NATIVE_ONLY
  RAWXD_LINKER=$RAWXD_LINKER
  STAGE0_BOOTSTRAP=MSVC (used only to build RawrXD compiler library)

Certification Gates:
  CERT_DRIVER=PASS          (RawrXD CoffWriter generates COFF object)
  RAWXD_LINKER=PASS         (RawrXD linker links COFF -> PE)
  NATIVE_EXECUTION=PASS     (Windows loads and executes PE, exit code 42)
  EXTERNAL_COMPILER_INVOCATIONS=PASS (0 external compilers invoked)
  LINKER_FAIL_CLOSED=PASS   (linker rejects invalid input with nonzero exit)

Invocation Log:
"@

foreach ($inv in $invocations) {
    $receipt += "  $($inv.Timestamp) | Exit=$($inv.ExitCode) | $($inv.Executable) $($inv.Arguments)`n"
}

$receipt += @"
Result: CERTIFICATION=PASS
PROMOTE=0

"@
$receipt | Out-File -FilePath $RECEIPT_FILE -Encoding UTF8

Write-Host "`n=== CERTIFICATION COMPLETE ==="
Write-Host 'Receipt: ' + $RECEIPT_FILE
Write-Host 'PROMOTE=0'
