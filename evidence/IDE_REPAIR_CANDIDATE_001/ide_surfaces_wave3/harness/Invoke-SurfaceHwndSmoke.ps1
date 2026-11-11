# Wave3 HWND smoke: launch Ext, post View panel cmds, probe IDC 1300/1312 visibility.
# No Build/CU/AgentCommands. PROMOTE=0. Fail-closed: NOT_RUN!=PASS.
param(
  [string]$TipExe = 'F:\rawrxd\release\RawrXD-readiness-rc5b\RawrXD-Win32IDE-Native-Ext.exe',
  [int]$SettleMs = 2500
)
$ErrorActionPreference = 'Continue'
$Root = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\ide_surfaces_wave3'
$OutDir = Join-Path $Root 'artifacts'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
if (-not (Test-Path -LiteralPath $TipExe)) { throw "TipExe missing: $TipExe" }

$sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$receipt = Join-Path $OutDir ("HWND_SMOKE_$stamp.txt")

Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;
public static class W3Hwnd {
  public const uint WM_COMMAND = 0x0111;
  public const uint WM_CLOSE = 0x0010;
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint wpid; GetWindowThreadProcessId(h, out wpid);
      if (wpid != pid || !IsWindowVisible(h)) return true;
      var sb = new StringBuilder(256);
      GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c == "RawrXD_IDE_Window" || c == "RawrXD_IDE_MainWindow") { found = h; return false; }
      if (found == IntPtr.Zero) found = h;
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static IntPtr FindId(IntPtr root, int id) {
    IntPtr f = IntPtr.Zero;
    EnumChildWindows(root, (h, lp) => { if (GetDlgCtrlID(h)==id){ f=h; return false;} return true; }, IntPtr.Zero);
    return f;
  }
}
"@

Get-Process -Name 'RawrXD-Win32IDE-Native*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
$p = Start-Process -FilePath $TipExe -PassThru -WindowStyle Normal
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 40; $i++) {
  Start-Sleep -Milliseconds 250
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; break }
  $main = [W3Hwnd]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) { break }
}

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))")
$lines.Add("SWARM=W3")
$lines.Add("GATE=W3_HWND_SMOKE")
$lines.Add("TIP_EXE=$TipExe")
$lines.Add("TIP_SHA256=$sha")
$lines.Add("PID=$($p.Id)")
$lines.Add("PROMOTE=0")

if ($p.HasExited -or $main -eq [IntPtr]::Zero) {
  $lines.Add("LAUNCH=FAIL")
  $lines.Add("VERDICT=FAIL_NO_HWND")
  $lines | Set-Content -LiteralPath $receipt -Encoding ASCII
  Write-Host "HWND_SMOKE=FAIL_NO_HWND receipt=$receipt"
  exit 1
}

$lines.Add("LAUNCH=PASS")
$lines.Add("MAIN_HWND=$main")
foreach ($cmd in @(2034, 2025, 2021, 2029)) {
  [void][W3Hwnd]::SendMessageW($main, 0x0111, [IntPtr]$cmd, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 200
}
Start-Sleep -Milliseconds $SettleMs

$id1300 = [W3Hwnd]::FindId($main, 1300)
$id1312 = [W3Hwnd]::FindId($main, 1312)
$vis1300 = if ($id1300 -ne [IntPtr]::Zero) { [W3Hwnd]::IsWindowVisible($id1300) } else { $false }
$vis1312 = if ($id1312 -ne [IntPtr]::Zero) { [W3Hwnd]::IsWindowVisible($id1312) } else { $false }
$lines.Add("CTRL_1300_PRESENT=$($id1300 -ne [IntPtr]::Zero)")
$lines.Add("CTRL_1300_VISIBLE=$vis1300")
$lines.Add("CTRL_1312_PRESENT=$($id1312 -ne [IntPtr]::Zero)")
$lines.Add("CTRL_1312_VISIBLE=$vis1312")

$ok = ($id1300 -ne [IntPtr]::Zero)
$verdict = if ($ok -and $vis1300) { 'PASS_DOCK_VISIBLE' }
           elseif ($ok) { 'PARTIAL_DOCK_PRESENT_HIDDEN' }
           else { 'FAIL_NO_PANEL_CONTAINER' }
$lines.Add("VERDICT=$verdict")
$lines.Add("NOTE=Smoke only; FOUR_PANEL_1_17 still required for band measure")

[void][W3Hwnd]::PostMessageW($main, [W3Hwnd]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
Start-Sleep 1
try { if (-not $p.HasExited) { $p.Kill() } } catch {}

$lines | Set-Content -LiteralPath $receipt -Encoding ASCII
Write-Host "HWND_SMOKE=$verdict receipt=$receipt"
if ($verdict -like 'PASS*') { exit 0 } else { exit 2 }
