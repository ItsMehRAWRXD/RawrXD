# P1_UI_MENU_E2E_001 â€” multi-leaf WM_COMMAND first-chance probe (no crash relaunch)
# Invokes deterministic menu ids with RAWRXD_P1_CMD_DIAG=1; stops on process death or FIRST_CHANCE.
$ErrorActionPreference = 'Stop'

function FmtExit([int]$ec) {
  $bytes = [BitConverter]::GetBytes($ec)
  return ('0x{0:X8}' -f [BitConverter]::ToUInt32($bytes, 0))
}' -f $u)
}

Get-Process RawrXD-Win32IDE -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

$bin = "F:\~dev\rawrxd\build-ninja\bin"
$ide = Join-Path $bin "RawrXD-Win32IDE.exe"
$crumbDir = Join-Path $bin "evidence\P1_UI_MENU_E2E_001"
$repoEv = "F:\~dev\rawrxd\evidence\P1_UI_MENU_E2E_001"
New-Item -ItemType Directory -Force -Path $crumbDir,$repoEv | Out-Null
Remove-Item -Force -ErrorAction SilentlyContinue `
  "$crumbDir\CMD_BREADCRUMB.txt","$crumbDir\FIRST_CHANCE_WM_COMMAND.txt",`
  "$crumbDir\COMMAND_FLIGHT.jsonl","$crumbDir\CMD_DIAG_ARMED.txt","$crumbDir\MULTI_LEAF_DIAG.txt",`
  "$crumbDir\IDE_GETTEXT_INFLIGHT.txt"

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $ide
$psi.WorkingDirectory = $bin
$psi.UseShellExecute = $false
$psi.EnvironmentVariables["RAWRXD_P1_CMD_DIAG"] = "1"
$psi.EnvironmentVariables["RAWRXD_P1_UI_MENU_E2E"] = "1"

Add-Type @"
using System; using System.Text; using System.Runtime.InteropServices;
public class CmdProbeMulti {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
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

# Non-exit, light-ish leaves (avoid IDM_APP_EXIT). Labels from ENUM / prior probes.
$leafs = @(
  @{ Id = 1001; Name = "File.New" },
  @{ Id = 1002; Name = "File.Open" },
  @{ Id = 1030; Name = "File.LoadModel" },
  @{ Id = 2016; Name = "Edit.Find" },
  @{ Id = 2020; Name = "View.Minimap" },
  @{ Id = 10400; Name = "Build.Solution" }
)

$sha = (Get-FileHash $ide -Algorithm SHA256).Hash
$proc = [System.Diagnostics.Process]::Start($psi)
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 120; $i++) {
  Start-Sleep -Seconds 1
  if ($proc.HasExited) { throw "exit early $(FmtExit $proc.ExitCode)" }
  $main = [CmdProbeMulti]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero) { break }
}
if ($main -eq [IntPtr]::Zero) { throw "NO_MAIN" }

# Poll settle â€” prior runs died 0xC000041D / 0xC0000374 here before any intentional leaf.
$settleDead = $false
for ($i = 0; $i -lt 20; $i++) {
  Start-Sleep -Seconds 1
  if ($proc.HasExited) {
    $settleDead = $true
    break
  }
}

$out = New-Object System.Collections.Generic.List[string]
$out.Add("EXE_SHA=$sha")
$out.Add("PID=$($proc.Id) MAIN=$main")
$out.Add("MODE=WM_COMMAND_LP0 CMD_DIAG=1 E2E=1 NO_RELAUNCH")
if ($settleDead) {
  $out.Add("STOP=PROCESS_DEAD during settle EXIT=$(FmtExit $proc.ExitCode)")
} else {
foreach ($leaf in $leafs) {
  if ($proc.HasExited) {
    $out.Add("STOP=PROCESS_DEAD before id=$($leaf.Id) EXIT=$(FmtExit $proc.ExitCode)")
    break
  }
  $id = [int]$leaf.Id
  $out.Add("--- INVOKE id=$id name=$($leaf.Name) ---")
  # Do not delete FIRST_CHANCE here â€” settle AV may already have written the localizer.
  [void][CmdProbeMulti]::SendMessageW($main, 0x0111, [IntPtr]$id, [IntPtr]::Zero)
  Start-Sleep -Seconds 2

  $alive = -not $proc.HasExited
  $fc = Join-Path $crumbDir "FIRST_CHANCE_WM_COMMAND.txt"
  $hasFc = Test-Path $fc
  $bc = Join-Path $crumbDir "CMD_BREADCRUMB.txt"
  $tail = ""
  if (Test-Path $bc) {
    $tail = ((Get-Content $bc) | Where-Object { $_ -match "id=$id " } | Select-Object -Last 8) -join " | "
  }
  $out.Add("PROCESS_ALIVE=$alive FIRST_CHANCE=$hasFc")
  if ($tail) { $out.Add("BREADCRUMB_TAIL=$tail") }
  if ($hasFc) {
    $out.Add("==== FIRST_CHANCE_CONTENT ====")
    $out.AddRange([string[]](Get-Content $fc))
    $out.Add("STOP=FIRST_CHANCE on id=$id ($($leaf.Name))")
    break
  }
  if (-not $alive) {
    $out.Add("STOP=PROCESS_DEAD after id=$id EXIT=$(FmtExit $proc.ExitCode)")
    break
  }
}
}

$fcFinal = Join-Path $crumbDir "FIRST_CHANCE_WM_COMMAND.txt"
$jrFinal = Join-Path $crumbDir "FIRST_CHANCE_JOURNAL.txt"
if (Test-Path $fcFinal) {
  $out.Add("==== FIRST_CHANCE_FINAL ====")
  $out.AddRange([string[]](Get-Content $fcFinal))
}
if (Test-Path $jrFinal) {
  $out.Add("==== JOURNAL_TAIL ====")
  $out.AddRange([string[]](Get-Content $jrFinal | Select-Object -Last 40))
}
if (Test-Path (Join-Path $crumbDir "CMD_BREADCRUMB.txt")) {
  $out.Add("==== BREADCRUMB_TAIL ====")
  $out.AddRange([string[]](Get-Content (Join-Path $crumbDir "CMD_BREADCRUMB.txt") | Select-Object -Last 25))
}

if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
$report = Join-Path $repoEv "MULTI_LEAF_DIAG.txt"
$out | Set-Content -Encoding utf8 $report
Copy-Item -Force "$crumbDir\*" $repoEv -ErrorAction SilentlyContinue
$out | ForEach-Object { Write-Host $_ }
Write-Host "WROTE $report"
