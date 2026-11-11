#Requires -Version 5.1
# Issue #49 map #11 — Package → clean-machine launch → rollback on tip_integ_candidate_001 (4DE0).
# Isolated deployable package; MAIN_HWND smoke from package dir; measured prior-package rollback.
# PROMOTE=0 MATURITY=82 E6CF HELD; NO_CROSS_SHA_PASS; tip006/A4F untouched.
$ErrorActionPreference = 'Continue'
$ExpectSha = '4DE06F9F0D7C4FA59926A1BD89041DB7FE75DE0332DBA783A968D3B4105D8BE6'
$PriorSha  = '4CFB85B3DD86602156D417FE367D82C84ABA5774AE3BD65FE2BA788614D70321'
$EvidenceRoot = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001'
$TipSrcDir = Join-Path $EvidenceRoot 'package\tip_integ_candidate_001'
$TipSrcExe = Join-Path $TipSrcDir 'RawrXD-Win32IDE-Native-Ext.exe'
$PriorPkgDir = 'F:\rawrxd\package\tip_integ_candidate_001'
$PriorExe = Join-Path $PriorPkgDir 'RawrXD-Win32IDE-Native-Ext.exe'
$OutDir = Join-Path $EvidenceRoot 'artifacts'
$CandDir = Join-Path $EvidenceRoot 'candidates\tip_integ_candidate_001'
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$RunId = "integ_map11_run_$Stamp"
$Session = "integ_map11_$Stamp"
$RunDir = Join-Path $CandDir "map11_pkg_clean_rollback_$Stamp"
$DeployDir = Join-Path $RunDir 'deploy_4DE0'
$RollbackDir = Join-Path $RunDir 'rollback_prior_4CFB'
$CleanUd = Join-Path $RunDir 'clean_userdata'
$RbUd = Join-Path $RunDir 'rollback_userdata'
$Journal = Join-Path $OutDir 'ISSUE49_PACKAGE_CLEAN_ROLLBACK_JOURNAL.txt'
$Receipt = Join-Path $OutDir 'ISSUE49_PACKAGE_CLEAN_ROLLBACK_RECEIPT.txt'
New-Item -ItemType Directory -Force -Path $RunDir, $DeployDir, $RollbackDir, $CleanUd, $RbUd, $OutDir | Out-Null

$j = New-Object System.Collections.Generic.List[string]
function J([string]$m) { $line = "$(Get-Date -Format o) $m"; $j.Add($line); Write-Host $line }

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class Map11CR {
  public const uint WM_CLOSE=0x0010;
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h,l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid || !IsWindowVisible(h)) return true;
      var sb = new StringBuilder(128); GetClassNameW(h, sb, sb.Capacity);
      if (sb.ToString().IndexOf("RawrXD") >= 0) { found = h; return false; }
      return true;
    }, IntPtr.Zero); return found;
  }
  public static bool CloseClean(IntPtr main, int waitMs) {
    if (main == IntPtr.Zero || !IsWindow(main)) return true;
    PostMessageW(main, WM_CLOSE, IntPtr.Zero, IntPtr.Zero);
    int slept = 0;
    while (slept < waitMs) {
      if (!IsWindow(main)) return true;
      System.Threading.Thread.Sleep(250); slept += 250;
    }
    return !IsWindow(main);
  }
}
"@

function Wait-Main($proc, [int]$sec) {
  $deadline = (Get-Date).AddSeconds($sec)
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { return [IntPtr]::Zero }
    $h = [Map11CR]::FindMain([UInt32]$proc.Id)
    if ($null -ne $h -and $h -ne [IntPtr]::Zero) { return $h }
    Start-Sleep -Milliseconds 250
  }
  return [IntPtr]::Zero
}
function Stop-Named {
  Get-Process -Name 'RawrXD-Win32IDE-Native-Ext','deep2_agentic_loop' -ErrorAction SilentlyContinue |
    Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Milliseconds 400
}
function Write-Manifest([string]$dir, [string]$path) {
  $lines = New-Object System.Collections.Generic.List[string]
  $lines.Add("ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))")
  $lines.Add("STAGE=$dir")
  Get-ChildItem $dir -Recurse -File | Sort-Object FullName | ForEach-Object {
    $rel = $_.FullName.Substring($dir.Length).TrimStart('\')
    $h = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
    $lines.Add("$h  $rel  $($_.Length)")
  }
  $lines -join "`n" | Set-Content -Path $path -Encoding UTF8
}

# --- SHA gate (authority tip; do not mutate tip package) ---
if (-not (Test-Path $TipSrcExe)) { J "MISSING_TIP=$TipSrcExe"; exit 9 }
$TipSha = (Get-FileHash -Algorithm SHA256 -Path $TipSrcExe).Hash
J "RUN_ID=$RunId EXPECT=$ExpectSha MEASURED=$TipSha TIP=$TipSrcExe"
if ($TipSha -ne $ExpectSha) { J "SHA_DRIFT=$TipSha"; exit 9 }
$ShaVerify = 'PASS'

# Prior package must remain 4CFB for rollback target (do not overwrite tip006/A4F).
$PriorMeasured = if (Test-Path $PriorExe) { (Get-FileHash -Algorithm SHA256 -Path $PriorExe).Hash } else { 'MISSING' }
J "PRIOR_PKG=$PriorExe PRIOR_SHA_EXPECT=$PriorSha PRIOR_SHA_MEASURED=$PriorMeasured"
$PriorOk = ($PriorMeasured -eq $PriorSha)

# --- 1) Produce deployable package (isolated; not developer build tree) ---
$required = @(
  'RawrXD-Win32IDE-Native-Ext.exe',
  'deep2_agentic_loop.exe',
  'META.txt',
  'SHA256.txt'
)
foreach ($name in $required) {
  $src = Join-Path $TipSrcDir $name
  if (Test-Path $src) { Copy-Item $src (Join-Path $DeployDir $name) -Force }
}
# Product sidecars / fixtures the tip package carries for smoke.
foreach ($extra in @('calc.cpp','ollama_runtime.log')) {
  $src = Join-Path $TipSrcDir $extra
  if (Test-Path $src) { Copy-Item $src (Join-Path $DeployDir $extra) -Force }
}
# Refresh SHA256.txt to measured tip SHA (stale stamp in source package noted).
Set-Content -Path (Join-Path $DeployDir 'SHA256.txt') -Encoding ascii -Value $TipSha
$DeployExe = Join-Path $DeployDir 'RawrXD-Win32IDE-Native-Ext.exe'
$DeploySha = (Get-FileHash -Algorithm SHA256 -Path $DeployExe).Hash
$Deep2Sha = (Get-FileHash -Algorithm SHA256 -Path (Join-Path $DeployDir 'deep2_agentic_loop.exe')).Hash
$ManPath = Join-Path $DeployDir 'SHA256_MANIFEST.txt'
Write-Manifest $DeployDir $ManPath
$PkgPass = if (($DeploySha -eq $ExpectSha) -and (Test-Path $ManPath) -and (Test-Path (Join-Path $DeployDir 'deep2_agentic_loop.exe'))) { 'PASS' } else { 'FAIL' }
J "PACKAGE=$PkgPass DEPLOY=$DeployDir DEPLOY_SHA=$DeploySha DEEP2_SHA=$Deep2Sha MANIFEST=$ManPath"

# Snapshot prior package into rollback staging (measured copy; source prior untouched).
if ($PriorOk) {
  Copy-Item (Join-Path $PriorPkgDir '*') $RollbackDir -Force -ErrorAction SilentlyContinue
  # Ensure EXE present even if wildcard skipped hidden
  Copy-Item $PriorExe (Join-Path $RollbackDir 'RawrXD-Win32IDE-Native-Ext.exe') -Force
  if (Test-Path (Join-Path $PriorPkgDir 'deep2_agentic_loop.exe')) {
    Copy-Item (Join-Path $PriorPkgDir 'deep2_agentic_loop.exe') (Join-Path $RollbackDir 'deep2_agentic_loop.exe') -Force
  }
}
$RbExe = Join-Path $RollbackDir 'RawrXD-Win32IDE-Native-Ext.exe'
$RbShaSnap = if (Test-Path $RbExe) { (Get-FileHash -Algorithm SHA256 -Path $RbExe).Hash } else { 'MISSING' }
$RbMan = Join-Path $RollbackDir 'SHA256_MANIFEST.txt'
if (Test-Path $RbExe) { Write-Manifest $RollbackDir $RbMan }
J "ROLLBACK_SNAP_SHA=$RbShaSnap"

# --- 2) Clean-machine / isolated-dir launch (no developer build tree cwd) ---
Stop-Named
$env:RAWRXD_DISCARD_UNSAVED_ON_CLOSE = '1'
$env:RAWRXD_LOG_DIR = (Join-Path $RunDir 'logs_clean')
New-Item -ItemType Directory -Force -Path $env:RAWRXD_LOG_DIR | Out-Null
$env:RAWRXD_CHAT_SESSION_ID = $Session
$env:RAWRXD_CHAT_RUN_ID = $RunId
# Prove package is self-contained: working directory = deploy package only.
$seed = Join-Path $DeployDir "map11_seed_$Stamp.txt"
Set-Content -Path $seed -Encoding ascii -Value "MAP11_CLEAN_$Stamp"
$argsClean = @($seed, "--user-data-dir=$CleanUd")
$pClean = Start-Process -FilePath $DeployExe -ArgumentList $argsClean -WorkingDirectory $DeployDir -PassThru -WindowStyle Minimized
J "CLEAN_LAUNCH_PID=$($pClean.Id) CWD=$DeployDir"
$mainClean = Wait-Main $pClean 55
$mainHex = '0x0'; $pidClean = $pClean.Id
$cleanLaunch = 'FAIL'
$haveCleanHwnd = ($null -ne $mainClean -and $mainClean -ne [IntPtr]::Zero -and -not $pClean.HasExited)
if ($haveCleanHwnd) {
  $mainHex = ('0x{0:X}' -f $mainClean.ToInt64())
  $cleanLaunch = 'PASS'
  J "CLEAN_MAIN_HWND=$mainHex"
  Start-Sleep 2
  [void][Map11CR]::CloseClean($mainClean, 12000)
} else {
  J "CLEAN_MAIN_HWND=MISSING exited=$($pClean.HasExited) code=$($pClean.ExitCode)"
}
if (-not $pClean.HasExited) {
  try { $pClean.CloseMainWindow() | Out-Null } catch {}
  Start-Sleep 2
  if (-not $pClean.HasExited) { Stop-Process -Id $pClean.Id -Force -ErrorAction SilentlyContinue }
}
Stop-Named
# Authority tip SHA must still be 5A34 after clean launch (no mutate).
$TipAfterClean = (Get-FileHash -Algorithm SHA256 -Path $TipSrcExe).Hash
J "TIP_AFTER_CLEAN=$TipAfterClean"

# --- 3) Rollback evidence: switch active deploy to prior package; hash before/after; relaunch ---
$ActiveSlot = Join-Path $RunDir 'active_deploy'
if (Test-Path $ActiveSlot) { Remove-Item $ActiveSlot -Recurse -Force -ErrorAction SilentlyContinue }
New-Item -ItemType Directory -Force -Path $ActiveSlot | Out-Null
Copy-Item (Join-Path $DeployDir '*') $ActiveSlot -Force
$ActiveExe = Join-Path $ActiveSlot 'RawrXD-Win32IDE-Native-Ext.exe'
$HashBefore = (Get-FileHash -Algorithm SHA256 -Path $ActiveExe).Hash
J "ROLLBACK_HASH_BEFORE=$HashBefore"
# Restore prior package into active slot (measured rollback procedure).
Get-ChildItem $ActiveSlot -File | Remove-Item -Force
Copy-Item (Join-Path $RollbackDir '*') $ActiveSlot -Force
$HashAfter = (Get-FileHash -Algorithm SHA256 -Path $ActiveExe).Hash
J "ROLLBACK_HASH_AFTER=$HashAfter"
$rollbackHashPass = ($HashBefore -eq $ExpectSha -and $HashAfter -eq $PriorSha -and $PriorOk)

$rbHwnd = '0x0'; $rbLaunch = 'FAIL'; $pidRb = 0
if ($rollbackHashPass) {
  $env:RAWRXD_LOG_DIR = (Join-Path $RunDir 'logs_rollback')
  New-Item -ItemType Directory -Force -Path $env:RAWRXD_LOG_DIR | Out-Null
  $seedRb = Join-Path $ActiveSlot "map11_rb_seed_$Stamp.txt"
  Set-Content -Path $seedRb -Encoding ascii -Value "MAP11_ROLLBACK_$Stamp"
  $pRb = Start-Process -FilePath $ActiveExe -ArgumentList @($seedRb, "--user-data-dir=$RbUd") -WorkingDirectory $ActiveSlot -PassThru -WindowStyle Minimized
  $pidRb = $pRb.Id
  J "ROLLBACK_LAUNCH_PID=$pidRb"
  $mainRb = Wait-Main $pRb 55
  $haveRbHwnd = ($null -ne $mainRb -and $mainRb -ne [IntPtr]::Zero -and -not $pRb.HasExited)
  if ($haveRbHwnd) {
    $rbHwnd = ('0x{0:X}' -f $mainRb.ToInt64())
    $rbLaunch = 'PASS'
    J "ROLLBACK_MAIN_HWND=$rbHwnd"
    Start-Sleep 2
    [void][Map11CR]::CloseClean($mainRb, 12000)
  } else {
    J "ROLLBACK_MAIN_HWND=MISSING exited=$($pRb.HasExited) code=$($pRb.ExitCode)"
  }
  if (-not $pRb.HasExited) {
    try { $pRb.CloseMainWindow() | Out-Null } catch {}
    Start-Sleep 2
    if (-not $pRb.HasExited) { Stop-Process -Id $pRb.Id -Force -ErrorAction SilentlyContinue }
  }
  Stop-Named
}
$RollbackPass = if ($rollbackHashPass -and $rbLaunch -eq 'PASS') { 'PASS' } else { 'FAIL' }
J "ROLLBACK=$RollbackPass HASH_GATE=$rollbackHashPass RELAUNCH=$rbLaunch"

# Authority tip package must remain 4DE0 (never overwritten by rollback staging).
$TipFinal = (Get-FileHash -Algorithm SHA256 -Path $TipSrcExe).Hash
$A4f = 'F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe'
$A4fSha = if (Test-Path $A4f) { (Get-FileHash -Algorithm SHA256 -Path $A4f).Hash } else { 'MISSING' }
J "TIP_FINAL=$TipFinal A4F_SHA=$A4fSha TIP_UNTOUCHED=$([bool]($TipFinal -eq $ExpectSha))"

$map11 = if ($ShaVerify -eq 'PASS' -and $PkgPass -eq 'PASS' -and $cleanLaunch -eq 'PASS' -and $RollbackPass -eq 'PASS' -and $TipFinal -eq $ExpectSha) { 'PASS' } else { 'FAIL' }
$score = if ($map11 -eq 'PASS') { '11/11' } else { '10/11' }
J "MAP11=$map11 SCORE=$score"

$asof = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
$receiptBody = @"
ISSUE49_PACKAGE_CLEAN_ROLLBACK_RECEIPT
ASOF_UTC=$asof
ACTIVE_TRACK=ISSUE_49
MAP=11
CANDIDATE=tip_integ_candidate_001
TIP_SHA256=$TipSha
PRIOR_SHA256=$PriorSha
TIP_EXE=$TipSrcExe
SUITE_STAMP=$Stamp
SESSION_ID=$Session
RUN_ID=$RunId
DEPLOY_PACKAGE=$DeployDir
DEPLOY_EXE=$DeployExe
DEPLOY_SHA256=$DeploySha
DEEP2_SHA256=$Deep2Sha
MANIFEST=$ManPath
HARNESS=artifacts\_issue49_package_clean_rollback_e2e.ps1
RUN_DIR=$RunDir
NO_CROSS_SHA_PASS=1
PROMOTE=0
MATURITY=82
E6CF_RESTORE=HELD
TIP_MOVE_AUTHORIZED=0
CC79_UNREPLACED=1
A4F_IMMUTABLE=1
A4F_SHA256=$A4fSha
INVENT_PASS=0

## SHA gate
SHA_VERIFY=$ShaVerify
EXPECTED=$ExpectSha
MEASURED=$TipSha
TIP_AFTER_CLEAN=$TipAfterClean
TIP_FINAL=$TipFinal
TIP_AUTHORITY_UNTOUCHED=$([bool]($TipFinal -eq $ExpectSha))

## Package (deployable)
PACKAGE=$PkgPass
REQUIRED_EXE=PASS
REQUIRED_DEEP2=$([bool](Test-Path (Join-Path $DeployDir 'deep2_agentic_loop.exe')))
MANIFEST_PRESENT=$([bool](Test-Path $ManPath))
ISOLATED_FROM_DEV_TREE=1
WORKING_DIRECTORY=$DeployDir

## Clean-machine / clean-profile launch
CLEAN_LAUNCH=$cleanLaunch
CLEAN_USER_DATA=$CleanUd
MAIN_HWND=$mainHex
PID_MAIN=$pidClean
SMOKE=MAIN_HWND

## Rollback (prior package 4CFB)
PRIOR_PKG=$PriorPkgDir
PRIOR_SHA_MEASURED=$PriorMeasured
ROLLBACK_SNAP=$RollbackDir
ROLLBACK_HASH_BEFORE=$HashBefore
ROLLBACK_HASH_AFTER=$HashAfter
ROLLBACK_HASH_GATE=$rollbackHashPass
ROLLBACK_RELAUNCH=$rbLaunch
ROLLBACK_MAIN_HWND=$rbHwnd
ROLLBACK_PID=$pidRb
ROLLBACK=$RollbackPass
ROLLBACK_PROCEDURE=active_slot_hash_before_4DE0_then_restore_prior_4CFB_relaunch

## Gate
MAP11=$map11
ISSUE49_ADVANCE=10/11->$score
ONE_SHA_REMEASURE_DEBT_MAPS_1_8=OPEN (historical 4CFB; NO_CROSS_SHA_PASS)
MAJOR_INTEGRATED_ACCEPTANCE=NOT_DEMONSTRATED
NOTE=11/11 map count != MAJOR_INTEGRATED_ACCEPTANCE without one-SHA conjunction
NEXT_GAP=$(if($map11 -eq 'PASS'){'ONE_SHA remasure maps1-11 on 4DE0 (NO_CROSS_SHA_PASS); MAJOR_INTEGRATED_ACCEPTANCE still NOT_DEMONSTRATED'}else{'Map #11 Package->clean-machine->rollback on SHA 4DE06F9F'})
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
"@
$receiptBody | Set-Content -Path $Receipt -Encoding UTF8
Copy-Item $Receipt (Join-Path $RunDir 'PACKAGE_CLEAN_ROLLBACK_RECEIPT.txt') -Force
$j -join "`n" | Set-Content -Path $Journal -Encoding UTF8
Write-Host "MAP11=$map11 RECEIPT=$Receipt"
exit $(if ($map11 -eq 'PASS') { 0 } else { 11 })
