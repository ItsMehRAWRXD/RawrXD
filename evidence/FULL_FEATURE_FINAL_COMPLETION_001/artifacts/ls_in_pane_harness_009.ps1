$__i49lock = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\ISSUE49_EXCLUSIVE.lock'
if (Test-Path -LiteralPath $__i49lock) {
  Write-Host 'SKIP: ISSUE49_EXCLUSIVE.lock present — not killing Native-Ext / not launching'
  exit 0
}
# LS_IN_PANE harness for tip_final_integ_009 â€” same-SHA seal; no PASS inheritance.
$ErrorActionPreference = 'Continue'
$exe = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_009\RawrXD-Win32IDE-Native-Ext.exe'
$cand = Split-Path $exe
$art = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runLog = Join-Path $art "ps_tip_009_ls_in_pane_run_$stamp.txt"
$receipt = 'F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\PS_TIP_REBUILD_LS_IN_PANE_RECEIPT.md'

function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content -Path $runLog -Value $line -Encoding UTF8
  Write-Output $line
}

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public static class PsTip009 {
  public const uint WM_CHAR=0x0102; public const uint WM_KEYDOWN=0x0100; public const uint WM_KEYUP=0x0101;
  public const uint WM_GETTEXT=0x000D; public const uint WM_GETTEXTLENGTH=0x000E; public const uint BM_CLICK=0x00F5;
  public const int VK_RETURN=0x0D;
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr l);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public delegate bool EnumChildProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h,uint m,IntPtr w,StringBuilder l);
  public static IntPtr FindMain(uint pid){
    IntPtr f=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint p; GetWindowThreadProcessId(h,out p); if(p!=pid||!IsWindowVisible(h)) return true;
      var sb=new StringBuilder(256); GetClassNameW(h,sb,sb.Capacity);
      if(sb.ToString().IndexOf("RawrXD",StringComparison.OrdinalIgnoreCase)>=0){f=h;return false;}
      if(f==IntPtr.Zero) f=h; return true; }, IntPtr.Zero);
    return f;
  }
  public static string GetText(IntPtr h){
    if(h==IntPtr.Zero) return "";
    int n=(int)SendMessageW(h,WM_GETTEXTLENGTH,IntPtr.Zero,IntPtr.Zero);
    if(n<=0){ var t=new StringBuilder(512); SendMessageW(h,WM_GETTEXT,(IntPtr)512,t); return t.ToString(); }
    if(n>120000) n=120000;
    var sb=new StringBuilder(n+2);
    SendMessageW(h,WM_GETTEXT,(IntPtr)(n+1),sb);
    return sb.ToString();
  }
  public static void TypeAscii(IntPtr h, string s){
    foreach(char c in s){ SendMessageW(h, WM_CHAR, (IntPtr)c, IntPtr.Zero); }
  }
}
"@

if (!(Test-Path $exe)) { throw "EXE_MISSING $exe" }
$sha = (Get-FileHash $exe -Algorithm SHA256).Hash.ToUpperInvariant()
Log "TIP_EXE=$exe"
Log "TIP_SHA256=$sha"
Log "INPUT_METHOD=WM_CHAR_KEYSTROKES"
Log "CMD=ls"

Get-Process -Name 'RawrXD-Win32IDE-Native*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
$env:RAWRXD_LOG_DIR = $cand
$p = Start-Process -FilePath $exe -WorkingDirectory $cand -PassThru -WindowStyle Normal
$main = [IntPtr]::Zero
for ($i=0; $i -lt 80; $i++) {
  Start-Sleep -Milliseconds 250
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "EARLY_EXIT code=$($p.ExitCode)"; break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; break }
  $main = [PsTip009]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) { break }
}
Log ("PID={0}" -f $p.Id)
Log ("MAIN_HWND=0x{0:X}" -f $main.ToInt64())
if ($main -eq [IntPtr]::Zero) { Log 'FAIL=NO_MAIN'; exit 2 }
[void][PsTip009]::ShowWindow($main, 5)
[void][PsTip009]::SetForegroundWindow($main)
Start-Sleep 3

$panel=[IntPtr]::Zero; $psOut=[IntPtr]::Zero; $psIn=[IntPtr]::Zero; $psExec=[IntPtr]::Zero
[PsTip009]::EnumChildWindows($main, {
  param($h,$lp)
  $id = [PsTip009]::GetDlgCtrlID($h)
  if ($id -eq 5600) { $script:panel = $h }
  if ($id -eq 5601) { $script:psOut = $h }
  if ($id -eq 5602) { $script:psIn = $h }
  if ($id -eq 5610) { $script:psExec = $h }
  return $true
}, [IntPtr]::Zero)

# Nested children under panel container
if ($panel -ne [IntPtr]::Zero) {
  [PsTip009]::EnumChildWindows($panel, {
    param($h,$lp)
    $id = [PsTip009]::GetDlgCtrlID($h)
    if ($id -eq 5601 -and $script:psOut -eq [IntPtr]::Zero) { $script:psOut = $h }
    if ($id -eq 5602 -and $script:psIn -eq [IntPtr]::Zero) { $script:psIn = $h }
    if ($id -eq 5610 -and $script:psExec -eq [IntPtr]::Zero) { $script:psExec = $h }
    return $true
  }, [IntPtr]::Zero)
}

Log ("PS_PANEL=0x{0:X}" -f $panel.ToInt64())
Log ("PS_OUT=0x{0:X}" -f $psOut.ToInt64())
Log ("PS_IN=0x{0:X}" -f $psIn.ToInt64())
Log ("PS_EXEC=0x{0:X}" -f $psExec.ToInt64())

$before = [PsTip009]::GetText($psOut)
Log ("PS_BEFORE_LEN={0}" -f $before.Length)
Log ("PS_BEFORE_SAMPLE=$($before.Substring(0,[Math]::Min(200,$before.Length)) -replace '`r|`n','\\n')")

if ($psIn -eq [IntPtr]::Zero) { Log 'FAIL=NO_PS_INPUT'; exit 3 }
[PsTip009]::TypeAscii($psIn, 'ls')
Start-Sleep -Milliseconds 200
$typed = [PsTip009]::GetText($psIn)
Log ("PS_INPUT_VERIFY='$typed' len=$($typed.Length)")
[void][PsTip009]::SendMessageW($psIn, [PsTip009]::WM_KEYDOWN, [IntPtr][PsTip009]::VK_RETURN, [IntPtr]::Zero)
[void][PsTip009]::SendMessageW($psIn, [PsTip009]::WM_KEYUP, [IntPtr][PsTip009]::VK_RETURN, [IntPtr]::Zero)
if ($psExec -ne [IntPtr]::Zero) {
  [void][PsTip009]::SendMessageW($psExec, [PsTip009]::BM_CLICK, [IntPtr]::Zero, [IntPtr]::Zero)
  Log 'EXEC_PATH=BM_CLICK_5610'
}

$after = ''
$foundListing = $false
$csiRaw = $false
for ($w=0; $w -lt 24; $w++) {
  Start-Sleep -Milliseconds 500
  $after = [PsTip009]::GetText($psOut)
  if ($after -match '(?i)(Directory|Mode\s+LastWriteTime|Name\s*$|\.exe|\.dll|\.cpp|\.ps1|Length)') { $foundListing = $true; break }
  if ($after -match '\x1b\[|\u001b\[|\[\?\d+[lh]|\]0;') { $csiRaw = $true }
}
Log ("PS_AFTER_LEN={0}" -f $after.Length)
$sample = if ($after.Length -gt 400) { $after.Substring(0,400) } else { $after }
Log ("PS_AFTER_SAMPLE=$($sample -replace '`r|`n','\\n')")
Log ("CSI_RAW_OBSERVED=$csiRaw")

$ls = if ($foundListing) { 'PASS' } else { 'FAIL_NO_DIR_LISTING' }
$console = if ($csiRaw) { 'FAIL_CSI_LITERAL' } elseif ($foundListing) { 'PASS_NO_RAW_CSI_MEASURED' } else { 'NOT_PROVEN' }
Log "LS_IN_PANE=$ls"
Log "CONSOLE_RENDERING=$console"
Log "SAME_BINARY_SHA=$sha"

try { Stop-Process -Id $p.Id -Force -EA SilentlyContinue } catch {}
exit $(if ($foundListing) { 0 } else { 4 })

