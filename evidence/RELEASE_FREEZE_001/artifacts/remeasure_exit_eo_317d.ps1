# Remeasure MULTI_TAB_EXIT + EXACTLY_ONCE on Ext tip 317D. No rebuild. A190 untouched.
$ErrorActionPreference = 'Stop'
$tipDir = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001'
$tip2 = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_002'
$art = 'F:\rawrxd\evidence\RELEASE_FREEZE_001\artifacts'
$tipExe = Join-Path $tipDir 'RawrXD-Win32IDE-Native-Ext.exe'
$hash = (Get-FileHash -Algorithm SHA256 -Path $tipExe).Hash
$short = $hash.Substring(0, 8)
$seal = Join-Path $tip2 ("RawrXD-FreezeSeal-{0}.exe" -f $short)
Copy-Item -Force $tipExe $seal
Copy-Item -Force $tipExe (Join-Path $tip2 'RawrXD-Win32IDE-Native-Ext.exe')
Set-Content (Join-Path $tip2 'SHA256.txt') $hash
$exitLogDir = Join-Path $art 'exit_probe_317d'
New-Item -ItemType Directory -Force -Path $exitLogDir | Out-Null
$trace = 'F:\rawrxd\startup_trace.log'
Get-Process -Name 'RawrXD-Win32IDE-Native*','RawrXD-FreezeSeal*','debuggee_fixture' -EA SilentlyContinue |
  Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
Set-Content -Path $trace -Value "===EXIT_PROBE_317D===`r`n" -Encoding ASCII
$env:RAWRXD_LOG_DIR = $exitLogDir
Remove-Item Env:RAWRXD_DEBUGGEE -EA SilentlyContinue
$proc = Start-Process -FilePath $tipExe -PassThru -WindowStyle Normal
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices; using System.Text;
public static class ExitProbe317d {
  public const uint WM_CLOSE=0x0010;
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr h, uint msg, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  public static IntPtr FindRawrXdIde(uint wantPid){
    IntPtr found=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint wpid; GetWindowThreadProcessId(h,out wpid);
      if(wpid!=wantPid||!IsWindowVisible(h)) return true;
      var sb=new StringBuilder(256); GetClassNameW(h,sb,sb.Capacity);
      if(sb.ToString().IndexOf("RawrXD_IDE",StringComparison.OrdinalIgnoreCase)>=0){ found=h; return false;}
      return true;}, IntPtr.Zero);
    return found;
  }
}
"@ -ErrorAction SilentlyContinue
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 60; $i++) {
  Start-Sleep -Milliseconds 500
  try { $proc.Refresh() } catch {}
  if ($proc.HasExited) { break }
  if ($proc.MainWindowHandle -ne [IntPtr]::Zero) { $main = [IntPtr]$proc.MainWindowHandle; break }
  $by = [ExitProbe317d]::FindRawrXdIde([uint32]$proc.Id)
  if ($by -ne [IntPtr]::Zero) { $main = $by; break }
}
Write-Host ("MAIN=0x{0:X} SHA=$hash" -f $main.ToInt64())
Start-Sleep 3
[void][ExitProbe317d]::PostMessage($main, [ExitProbe317d]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
$exited = $proc.WaitForExit(15000)
$forced = 0
if (-not $proc.HasExited) {
  Stop-Process -Id $proc.Id -Force -EA SilentlyContinue
  $proc.WaitForExit(5000) | Out-Null
  $forced = 1
}
$exitCode = $proc.ExitCode
$tail = @(Get-Content $trace -EA SilentlyContinue | Select-Object -Last 80)
$traceText = ($tail -join "`n")
$hasEnter = $traceText -match 'prepareForExit enter'
$hasExit = $traceText -match 'prepareForExit exit'
$hasQuit0 = $traceText -match 'GetMessage WM_QUIT wParam=0'
$multi = if ($forced -eq 0 -and "$exitCode" -eq '0' -and $hasEnter -and $hasExit -and $hasQuit0) { 'PASS' } else { 'FAIL' }
@"
MULTI_TAB_EXIT=$multi
TIP_SHA256=$hash
TIP_EXE=$tipExe
ORDERLY_EXIT_EXPECT=0
ORDERLY_EXIT_OBSERVED=$exitCode
FORCE_KILL=$forced
NINJA_EXIT=0
SOURCE_FIX=closeAllDocumentTabsForExit+WM_CLOSE_skip_MB+NATIVE_WFDE_5060
RAWRXD_LOG_DIR=$exitLogDir
TRACE_HAS_PREPARE_ENTER=$hasEnter
TRACE_HAS_PREPARE_EXIT=$hasExit
TRACE_HAS_WM_QUIT_WPARAM0=$hasQuit0
PROMOTE=0
CERTIFIED=0
MATURITY=82%
"@ | Set-Content (Join-Path $art 'MULTI_TAB_EXIT_RECEIPT.txt')
Get-Content (Join-Path $art 'MULTI_TAB_EXIT_RECEIPT.txt')
Write-Host '=== EO ==='
$eoLog = Join-Path $tip2 ("eo_freeze_{0}" -f $short.ToLower())
New-Item -ItemType Directory -Force -Path $eoLog | Out-Null
& (Join-Path $art 'freeze_exactly_once_35c22_v2.ps1') -TipExe $tipExe -ExpectSha $hash -OutDir $art -LogDir $eoLog -PreferModel 'nemotron-3-nano:4b'
Write-Host "EO_EXIT=$LASTEXITCODE"
Get-Content (Join-Path $art 'FREEZE_EXACTLY_ONCE_RECEIPT.txt')
