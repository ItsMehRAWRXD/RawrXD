# TIP_GUI_CREATEWINDOW_748B_001 — prove tip freeze createWindow → MAIN_HWND
# PROMOTE=0 TIP_CLIMB=HOLD CERTIFIED=0 ABSORB_GHOSTTEXT=NOT_AUTHORIZED
# FREEZE_UNTOUCHED=1 REBUILD_THIS_DISPATCH=0
$ErrorActionPreference = "Continue"
$OutDir = "G:\~dev\rawrxd\evidence\TIP_GUI_CREATEWINDOW_748B_001"
$TipExe = "G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe"
$ExpectedSha = "748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145"
$ClassName = "RawrXD_IDE_MainWindow"
New-Item -ItemType Directory -Force -Path $OutDir, (Join-Path $OutDir "logs") | Out-Null
if (-not (Test-Path -LiteralPath $TipExe)) { Write-Error "TIP_EXE_MISSING"; exit 2 }
$sha = (Get-FileHash -LiteralPath $TipExe -Algorithm SHA256).Hash
Set-Content (Join-Path $OutDir "logs\exe_sha.txt") $sha
if ($sha -ne $ExpectedSha) { Write-Error "SHA_DRIFT actual=$sha"; exit 3 }
"MATCH=1 EXPECTED=$ExpectedSha" | Set-Content (Join-Path $OutDir "logs\sha_match.txt")
Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue | ForEach-Object {
  Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 2
$cs = @'
using System; using System.Text; using System.Runtime.InteropServices;
public class TipHwnd748BHarness {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  public static IntPtr FindMainByPid(uint pid, string className) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid) return true;
      var cls = new StringBuilder(256); GetClassNameW(h, cls, 256);
      if (cls.ToString() == className) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static string Title(IntPtr h) { var b=new StringBuilder(512); GetWindowTextW(h,b,512); return b.ToString(); }
}
'@
Add-Type -TypeDefinition $cs -ErrorAction SilentlyContinue | Out-Null
$Stdout = Join-Path $OutDir "logs\gui_stdout.txt"
$Stderr = Join-Path $OutDir "logs\gui_stderr.txt"
$env:RAWRXD_GUI = "1"
Remove-Item Env:RAWRXD_HEADLESS -ErrorAction SilentlyContinue
$p = Start-Process -FilePath $TipExe -WorkingDirectory (Split-Path $TipExe) `
  -RedirectStandardOutput $Stdout -RedirectStandardError $Stderr -PassThru -WindowStyle Normal
"PID=$($p.Id) LAUNCH_UTC=$((Get-Date).ToUniversalTime().ToString('o'))" |
  Set-Content (Join-Path $OutDir "logs\launch.txt")
$hwnd = [IntPtr]::Zero; $tick = 0
$deadline = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $deadline) {
  if ($p.HasExited) { break }
  $hwnd = [TipHwnd748BHarness]::FindMainByPid([uint32]$p.Id, $ClassName)
  if ($hwnd -ne [IntPtr]::Zero) { break }
  Start-Sleep -Milliseconds 250; $tick++
}
$aliveAtFind = (-not $p.HasExited)
$title = if ($hwnd -ne [IntPtr]::Zero) { [TipHwnd748BHarness]::Title($hwnd) } else { "" }
Start-Sleep -Seconds 2
$procAliveEnd = (-not $p.HasExited)
$exitCode = if ($p.HasExited) { "$($p.ExitCode)" } else { "" }
$hwndHex = ("0x{0:X}" -f $hwnd.ToInt64())
"MAIN_HWND=$hwndHex tick=$tick alive_at_find=$(if($aliveAtFind){'1'}else{'0'}) proc_alive_end=$procAliveEnd pid=$($p.Id) exited=$($p.HasExited) exit=$exitCode title=$title" |
  Set-Content (Join-Path $OutDir "logs\hwnd_result.txt")
"$hwndHex|$ClassName|$title" | Set-Content (Join-Path $OutDir "logs\top_windows.txt")
if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
if ($hwnd -eq [IntPtr]::Zero) { exit 4 }
exit 0
