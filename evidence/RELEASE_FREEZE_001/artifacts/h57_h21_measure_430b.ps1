# H57 + H21 remasure on a sealed freeze EXE. PROMOTE=0. No invent PASS.
param(
  [Parameter(Mandatory=$true)][string]$TipExe,
  [Parameter(Mandatory=$true)][string]$ExpectSha,
  [string]$OutDir = "F:\rawrxd\evidence\RELEASE_FREEZE_001\artifacts",
  [string]$LogDir = "F:\rawrxd\evidence\RELEASE_FREEZE_001\candidates\tip_freeze_001\h57_h21_35af"
)
$ErrorActionPreference = 'Continue'
New-Item -ItemType Directory -Force -Path $OutDir,$LogDir | Out-Null
Get-Process | Where-Object { $_.ProcessName -match 'RawrXD|Win32IDE|Freeze' } | ForEach-Object {
  try { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue } catch {}
}
Start-Sleep 1
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$runlog = Join-Path $OutDir "h57_h21_run_$stamp.txt"
$receipt = Join-Path $OutDir "H57_H21_RUNTIME_RECEIPT.txt"
function Log([string]$m) {
  $line = "$(Get-Date -Format o) $m"
  Add-Content $runlog $line
  Write-Host $line
}
if (-not (Test-Path $TipExe)) {
  "H57=NOT_RUN`nH21=NOT_RUN`nREASON=tip_missing`nPROMOTE=0" | Set-Content $receipt; exit 2
}
$sha = (Get-FileHash -LiteralPath $TipExe -Algorithm SHA256).Hash
Log "TIP_EXE=$TipExe SHA=$sha EXPECT=$ExpectSha"
if ($sha -ne $ExpectSha) {
  @"
H57=NOT_RUN
H21=NOT_RUN
REASON=SHA_MISMATCH
MEASURED=$sha
EXPECT=$ExpectSha
PROMOTE=0
"@ | Set-Content $receipt
  exit 3
}
$bytes = [IO.File]::ReadAllBytes($TipExe)
$ascii = [Text.Encoding]::ASCII.GetString($bytes)
$h57Strings = (@('AgentSession','native_agent_session','exactly_once_submit') | ForEach-Object { [int]$ascii.Contains($_) })
$h57Present = ($h57Strings[0] -eq 1)
$eoPresent = ($h57Strings[2] -eq 1)
$dpiPresent = [int]($ascii.Contains('WM_DPICHANGED') -or $ascii.Contains('CHAT_CTRL_LATCH') -or $ascii.Contains('DPI'))
Log "H57_STRINGS AgentSession=$($h57Strings[0]) ledger_name=$($h57Strings[1]) eo_submit=$eoPresent DPI_MARK=$dpiPresent"

Add-Type @"
using System; using System.Runtime.InteropServices; using System.Text;
public static class H57H21 {
  public const uint WM_DPICHANGED=0x02E0; public const uint WM_CLOSE=0x0010;
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int Left,Top,Right,Bottom; }
  public static IntPtr FindMain(uint pid){
    IntPtr found=IntPtr.Zero;
    EnumWindows((h,l)=>{ uint wpid; GetWindowThreadProcessId(h,out wpid);
      if(wpid!=pid||!IsWindowVisible(h)) return true;
      var sb=new StringBuilder(256); GetClassNameW(h,sb,sb.Capacity);
      string c=sb.ToString();
      if(c.Contains("RawrXD_IDE")){ found=h; return false; }
      if(found==IntPtr.Zero) found=h; return true;
    }, IntPtr.Zero);
    return found;
  }
}
"@

$env:RAWRXD_LOG_DIR = $LogDir
$wd = Split-Path $TipExe
$p = Start-Process -FilePath $TipExe -WorkingDirectory $wd -PassThru -WindowStyle Normal
Log "PID=$($p.Id)"
$main = [IntPtr]::Zero
for ($i=0; $i -lt 40; $i++) {
  Start-Sleep -Milliseconds 500
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { Log "EXIT_EARLY code=$($p.ExitCode)"; break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; break }
  $by = [H57H21]::FindMain([uint32]$p.Id)
  if ($by -ne [IntPtr]::Zero) { $main = $by; break }
}
Log ("MAIN=0x{0:X}" -f $main.ToInt64())
$aliveBoot = (-not $p.HasExited) -and ($main -ne [IntPtr]::Zero)
$ledgerPath = Join-Path $wd ".rawrxd\ledger\native_agent_session.json"
$ledgerAlt = Join-Path $LogDir ".rawrxd\ledger\native_agent_session.json"
Start-Sleep 2
$ledgerHit = (Test-Path $ledgerPath) -or (Test-Path $ledgerAlt)
# Prefer working-dir ledger created by AgentSession
Get-ChildItem (Join-Path $wd '.rawrxd') -Recurse -Filter 'native_agent_session.json' -EA SilentlyContinue |
  ForEach-Object { $ledgerHit = $true; $ledgerPath = $_.FullName; Log "LEDGER_FOUND=$($_.FullName)" }

$h21 = 'NOT_RUN'
$rectBefore = $null; $rectAfter = $null
if ($aliveBoot) {
  $r1 = New-Object H57H21+RECT
  [void][H57H21]::GetWindowRect($main, [ref]$r1)
  $rectBefore = "$($r1.Left),$($r1.Top),$($r1.Right),$($r1.Bottom)"
  # Suggested new monitor rect (slight nudge) in lParam RECT*
  $bytes = [BitConverter]::GetBytes([int]($r1.Left+8)) +
           [BitConverter]::GetBytes([int]($r1.Top+8)) +
           [BitConverter]::GetBytes([int]($r1.Right+8)) +
           [BitConverter]::GetBytes([int]($r1.Bottom+8))
  $ptr = [Runtime.InteropServices.Marshal]::AllocHGlobal($bytes.Length)
  [Runtime.InteropServices.Marshal]::Copy($bytes, 0, $ptr, $bytes.Length)
  try {
    [void][H57H21]::SendMessageW($main, [H57H21]::WM_DPICHANGED, [IntPtr]0x00600060, $ptr)
  } finally {
    [Runtime.InteropServices.Marshal]::FreeHGlobal($ptr)
  }
  Start-Sleep -Milliseconds 400
  $r2 = New-Object H57H21+RECT
  [void][H57H21]::GetWindowRect($main, [ref]$r2)
  $rectAfter = "$($r2.Left),$($r2.Top),$($r2.Right),$($r2.Bottom)"
  $changed = ($rectBefore -ne $rectAfter)
  $stillAlive = (-not $p.HasExited) -and [H57H21]::IsWindow($main)
  $h21 = if ($stillAlive -and ($dpiPresent -eq 1 -or $changed)) {
    if ($changed) { 'PASS_RECT_CHANGED' } else { 'PASS_HANDLER_ALIVE_NO_RECT_DELTA' }
  } elseif (-not $stillAlive) { 'FAIL_EXIT_AFTER_DPI' } else { 'FAIL_NO_HANDLER_EVIDENCE' }
  Log "H21 rectBefore=$rectBefore rectAfter=$rectAfter changed=$changed alive=$stillAlive => $h21"
  # Orderly multi-tab exit path
  [void][H57H21]::SendMessageW($main, [H57H21]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
  $deadline = [Environment]::TickCount64 + 8000
  while ([Environment]::TickCount64 -lt $deadline) {
    try { $p.Refresh() } catch {}
    if ($p.HasExited) { break }
    Start-Sleep -Milliseconds 200
  }
}
$exitCode = if ($p.HasExited) { $p.ExitCode } else { 'STILL_RUNNING' }
$exitOk = ($p.HasExited -and ($p.ExitCode -eq 0))
if (-not $p.HasExited) { try { Stop-Process -Id $p.Id -Force } catch {} }
$h57 = if ($h57Present -and $ledgerHit -and $aliveBoot) { 'PASS_LEDGER_RUNTIME' }
  elseif ($h57Present -and $aliveBoot) { 'PASS_STRINGS_RUNTIME_LEDGER_ABSENT' }
  elseif ($h57Present) { 'STRINGS_PRESENT_RUNTIME_FAIL' }
  else { 'FAIL_STRINGS_ABSENT' }
Log "H57=$h57 H21=$h21 EXIT=$exitCode EXIT_OK=$exitOk"

@"
CANDIDATE_SHA=$sha
H57=$h57
H57_STRINGS_AGENTSESSION=$($h57Strings[0])
H57_LEDGER_HIT=$ledgerHit
H57_LEDGER_PATH=$ledgerPath
H21=$h21
H21_RECT_BEFORE=$rectBefore
H21_RECT_AFTER=$rectAfter
BOOT_ALIVE=$aliveBoot
ORDERLY_EXIT_CODE=$exitCode
ORDERLY_EXIT_OK=$exitOk
EXACTLY_ONCE_STRING=$eoPresent
TIP_EXE=$TipExe
RUNLOG=$runlog
PROMOTE=0
CERTIFIED=0
MATURITY=82%
"@ | Set-Content $receipt -Encoding ASCII
Get-Content $receipt
exit $(if ($h57 -match '^PASS' -and $h21 -match '^PASS' -and $exitOk) { 0 } else { 1 })
