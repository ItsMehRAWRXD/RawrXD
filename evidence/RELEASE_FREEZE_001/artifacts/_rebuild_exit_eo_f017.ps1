# Rebuild Native-Ext after BOTH exit fixes; stage tip; exit probe; EO remasure.
# Fixes required in binary:
#   1) closeAllDocumentTabsForExit — no removeDocumentTab untitled-recreate hang
#   2) WM_CLOSE/SC_CLOSE — skip MessageBox when RAWRXD_LOG_DIR is set
# PROMOTE=0 MATURITY=82% NO_CROSS_SHA_PASS_INHERITANCE=1 — never overwrite A190 pin EXEs.
$ErrorActionPreference = "Stop"
$buildDir = "F:\rawrxd\.worktrees\release-freeze-001\build_release_freeze_001"
$tipDir = "F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001"
$tip2 = "F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_002"
$art = "F:\rawrxd\evidence\RELEASE_FREEZE_001\artifacts"
$trace = "F:\rawrxd\startup_trace.log"
$exitLogDir = Join-Path $art "exit_probe_logdir"
New-Item -ItemType Directory -Force -Path $tipDir, $tip2, $art, $exitLogDir | Out-Null

Write-Host "=== REBUILD ==="
$pRebuild = Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$buildDir\_one_rebuild.bat`"" -WorkingDirectory $buildDir -Wait -PassThru -NoNewWindow
$ninjaExit = $pRebuild.ExitCode
Write-Host "REBUILD_EXIT=$ninjaExit NINJA_EXIT=$ninjaExit"
$built = Get-ChildItem -Path $buildDir -Recurse -Filter "RawrXD-Win32IDE-Native-Ext.exe" -EA SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1
if (-not $built) { throw "BUILT_EXE_MISSING" }
Write-Host "BUILT=$($built.FullName) LW=$($built.LastWriteTimeUtc)"

$tipExe = Join-Path $tipDir "RawrXD-Win32IDE-Native-Ext.exe"
# Never touch A190 / RXD_PIN_A190_* pins
Copy-Item -Force $built.FullName $tipExe
$hash = (Get-FileHash -Algorithm SHA256 -Path $tipExe).Hash
Set-Content (Join-Path $tipDir "SHA256.txt") $hash
$short = $hash.Substring(0, 8)
$seal = Join-Path $tip2 ("RawrXD-FreezeSeal-{0}.exe" -f $short)
Copy-Item -Force $tipExe $seal
Copy-Item -Force $tipExe (Join-Path $tip2 "RawrXD-Win32IDE-Native-Ext.exe")
Set-Content (Join-Path $tip2 "SHA256.txt") $hash
Write-Host "STAGED_SHA=$hash SEAL=$seal"

Write-Host "=== EXIT_PROBE ==="
Get-Process -Name "RawrXD-Win32IDE-Native-Ext","RawrXD-FreezeSeal*" -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep -Seconds 1
Set-Content -Path $trace -Value "===EXIT_PROBE_START===`r`n" -Encoding ASCII
# Harness gate: RAWRXD_LOG_DIR skips unsaved MessageBox on WM_CLOSE/SC_CLOSE
$env:RAWRXD_LOG_DIR = $exitLogDir
$proc = Start-Process -FilePath $tipExe -PassThru -WindowStyle Normal
$procId = $proc.Id

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class ExitProbeF017 {
  public const uint WM_CLOSE = 0x0010;
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  public static IntPtr FindRawrXdIde(uint wantPid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint wpid; GetWindowThreadProcessId(h, out wpid);
      if (wpid != wantPid || !IsWindowVisible(h)) return true;
      var sb = new StringBuilder(256);
      GetClassNameW(h, sb, sb.Capacity);
      if (sb.ToString().IndexOf("RawrXD_IDE", StringComparison.OrdinalIgnoreCase) >= 0) {
        found = h; return false;
      }
      return true;
    }, IntPtr.Zero);
    return found;
  }
}
"@ -ErrorAction SilentlyContinue

$main = [IntPtr]::Zero
for ($i = 0; $i -lt 60; $i++) {
  Start-Sleep -Milliseconds 500
  try { $proc.Refresh() } catch {}
  if ($proc.HasExited) { break }
  if ($proc.MainWindowHandle -ne [IntPtr]::Zero) {
    $main = [IntPtr]$proc.MainWindowHandle
    break
  }
  $byClass = [ExitProbeF017]::FindRawrXdIde([uint32]$procId)
  if ($byClass -ne [IntPtr]::Zero) { $main = $byClass; break }
}
Write-Host ("MAIN=0x{0:X} PROC={1}" -f $main.ToInt64(), $procId)
if ($main -eq [IntPtr]::Zero) {
  @"
MULTI_TAB_EXIT=FAIL
TIP_SHA256=$hash
ORDERLY_EXIT_OBSERVED=NO_HWND
NINJA_EXIT=$ninjaExit
PROMOTE=0
CERTIFIED=0
MATURITY=82%
"@ | Set-Content (Join-Path $art "MULTI_TAB_EXIT_RECEIPT.txt")
  throw "NO_MAIN_HWND"
}

# Brief settle so session restore / tabs finish before close
Start-Sleep -Seconds 3
[void][ExitProbeF017]::PostMessage($main, [ExitProbeF017]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
$exited = $proc.WaitForExit(15000)
$exitCode = if ($proc.HasExited) { $proc.ExitCode } else { "STILL_ALIVE" }
if (-not $proc.HasExited) {
  Stop-Process -Id $procId -Force -EA SilentlyContinue
  $proc.WaitForExit(5000) | Out-Null
  $exitCode = $proc.ExitCode
  $forced = 1
} else { $forced = 0 }
Write-Host "EXIT_CODE=$exitCode FORCED=$forced WAIT_OK=$exited"
$tail = @(Get-Content $trace -EA SilentlyContinue | Select-Object -Last 60)
$tail | ForEach-Object { Write-Host $_ }
$traceText = ($tail -join "`n")
$hasEnter = $traceText -match 'prepareForExit enter'
$hasExit = $traceText -match 'prepareForExit exit'
$hasQuit0 = $traceText -match 'GetMessage WM_QUIT wParam=0'
$multi = if ($forced -eq 0 -and "$exitCode" -eq "0" -and $hasEnter -and $hasExit -and $hasQuit0) { "PASS" } else { "FAIL" }
@"
MULTI_TAB_EXIT=$multi
TIP_SHA256=$hash
TIP_EXE=$tipExe
ORDERLY_EXIT_EXPECT=0
ORDERLY_EXIT_OBSERVED=$exitCode
FORCE_KILL=$forced
NINJA_EXIT=$ninjaExit
SOURCE_FIX=closeAllDocumentTabsForExit_no_untitled_recreate+WM_CLOSE_skip_MessageBox_when_RAWRXD_LOG_DIR
RAWRXD_LOG_DIR=$exitLogDir
TRACE_HAS_PREPARE_ENTER=$hasEnter
TRACE_HAS_PREPARE_EXIT=$hasExit
TRACE_HAS_WM_QUIT_WPARAM0=$hasQuit0
PROMOTE=0
CERTIFIED=0
MATURITY=82%
"@ | Set-Content (Join-Path $art "MULTI_TAB_EXIT_RECEIPT.txt")

Write-Host "=== EXACTLY_ONCE ==="
$eoScript = Join-Path $art "freeze_exactly_once_35c22_v2.ps1"
$logDir = Join-Path $tip2 ("eo_freeze_{0}" -f $short.ToLower())
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
& $eoScript -TipExe $tipExe -ExpectSha $hash -OutDir $art -LogDir $logDir -PreferModel "nemotron-3-nano:4b"
$eoExit = $LASTEXITCODE
Write-Host "EO_SCRIPT_EXIT=$eoExit"
Write-Host "DONE_SHA=$hash MULTI=$multi EXIT_CODE=$exitCode NINJA_EXIT=$ninjaExit EO_EXIT=$eoExit"
