# Multi-trial close + close-after-File.New (CLOSE_TEARDOWN reopened).
function FmtExit([int]$ec) {
  $bytes = [BitConverter]::GetBytes($ec)
  return ('0x{0:X8}' -f [BitConverter]::ToUInt32($bytes, 0))
}
$ErrorActionPreference = 'Stop'
Get-Process RawrXD-Win32IDE -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

$bin = "F:\~dev\rawrxd\build-ninja\bin"
$ide = Join-Path $bin "RawrXD-Win32IDE.exe"
$repoEv = "F:\~dev\rawrxd\evidence\P1_UI_MENU_E2E_001"
$crumbDir = Join-Path $bin "evidence\P1_UI_MENU_E2E_001"
$out = Join-Path $repoEv "CLOSE_TEARDOWN_MULTI.txt"
New-Item -ItemType Directory -Force -Path $crumbDir,$repoEv | Out-Null

$sha = (Get-FileHash $ide -Algorithm SHA256).Hash
Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public class CloseMulti {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid) return true;
      var sb = new StringBuilder(256);
      GetClassName(h, sb, 256);
      if (sb.ToString() == "RawrXD_IDE_MainWindow" && IsWindowVisible(h)) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
}
"@

function OneClose([string]$tag, [bool]$fileNew, [int]$settleSec) {
  Get-Process RawrXD-Win32IDE -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 1
  Remove-Item -Force -ErrorAction SilentlyContinue `
    "$crumbDir\CMD_BREADCRUMB.txt","$crumbDir\FIRST_CHANCE_WM_COMMAND.txt","$crumbDir\FIRST_CHANCE_JOURNAL.txt"
  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $ide
  $psi.WorkingDirectory = $bin
  $psi.UseShellExecute = $false
  $psi.EnvironmentVariables["RAWRXD_P1_UI_MENU_E2E"] = "1"
  $psi.EnvironmentVariables["RAWRXD_P1_CMD_DIAG"] = "1"
  $proc = [System.Diagnostics.Process]::Start($psi)
  $main = [IntPtr]::Zero
  for ($i = 0; $i -lt 90; $i++) {
    Start-Sleep -Seconds 1
    if ($proc.HasExited) {
      return "$tag EXIT_BEFORE_MAIN=$(FmtExit $proc.ExitCode) ncd=False bad=True"
    }
    $main = [CloseMulti]::FindMain([uint32]$proc.Id)
    if ($main -ne [IntPtr]::Zero) { break }
  }
  if ($main -eq [IntPtr]::Zero) {
    if (-not $proc.HasExited) { $proc.Kill(); $proc.WaitForExit(5000) | Out-Null }
    return "$tag NO_MAIN"
  }
  Start-Sleep -Seconds $settleSec
  if ($proc.HasExited) {
    return "$tag DIED_SETTLE=$(FmtExit $proc.ExitCode) ncd=False bad=True"
  }
  if ($fileNew) {
    [void][CloseMulti]::SendMessageW($main, 0x0111, [IntPtr]1001, [IntPtr]::Zero)
    Start-Sleep -Seconds 2
    if ($proc.HasExited) {
      return "$tag DIED_AFTER_FILENEW=$(FmtExit $proc.ExitCode) ncd=False bad=True"
    }
  }
  [void][CloseMulti]::PostMessageW($main, 0x0010, [IntPtr]::Zero, [IntPtr]::Zero)
  if (-not $proc.WaitForExit(60000)) {
    $proc.Kill()
    $proc.WaitForExit(10000) | Out-Null
    return "$tag CLOSE_TIMEOUT exit=$(FmtExit $proc.ExitCode) ncd=False bad=True"
  }
  $ex = FmtExit $proc.ExitCode
  $ncd = $false
  $last = "?"
  $bc = Join-Path $crumbDir "CMD_BREADCRUMB.txt"
  if (Test-Path $bc) {
    $ncd = Select-String -Path $bc -Pattern "WM_NCDESTROY_AFTER_onDestroy" -Quiet
    $win = Select-String -Path $bc -Pattern "WINMAIN_RETURN" -Quiet
    $lastC = Get-Content $bc | Where-Object { $_ -match 'id=-1 step=' } | Select-Object -Last 1
    if ($lastC) { $last = $lastC }
  } else { $win = $false }
  $bad = @('0xC0000005','0xC000041D','0xC0000409','0xC0000374') -contains $ex.ToUpper()
  return "$tag exit=$ex bad=$bad ncd=$ncd winmain=$win last=$last"
}

$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("P1_UI_MENU_E2E_001 CLOSE_TEARDOWN_MULTI")
$lines.Add("SHA256=$sha")
$lines.Add("TEARDOWN_EXONERATED=NO")
$badCount = 0
for ($t = 1; $t -le 6; $t++) {
  $r = OneClose "T$t" $false 4
  $lines.Add($r)
  Write-Host $r
  if ($r -match 'bad=True') { $badCount++ }
}
$r7 = OneClose "T7_AFTER_FILENEW" $true 8
$lines.Add($r7)
Write-Host $r7
if ($r7 -match 'bad=True') { $badCount++ }

$lines.Add("BAD_COUNT=$badCount")
$lines.Add("CLOSE_TEARDOWN_STABLE=$( $badCount -eq 0 )")
$lines | Set-Content $out -Encoding UTF8
Write-Host "WROTE $out BAD_COUNT=$badCount"
