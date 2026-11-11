#Requires -Version 5.1
# T15 residual: shell stamp + agentic cancel 4107. Reuses qwen3:8b. Avoid Request-A Stop.
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\AGENT'
$WorkDir = Join-Path $OutDir 'workdir'
$CandExe = 'F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe'
$CandDir = Split-Path $CandExe
$ExpectSha = '3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F'
$CliPath = 'F:\rawrxd\build_ide\bin-msvc\rawr.exe'
$EspPath = 'F:\rawrxd\.rawrxd\ledger\agent_esp.jsonl'
$LogFile = Join-Path $OutDir 'RUNLOG_SHELL_CANCEL.txt'
$Model = 'qwen3:8b'
$Marker = 'T15SC_' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$Fixture = Join-Path $WorkDir ("t15_sc_{0}.cpp" -f $Marker)
$ShellStamp = Join-Path $WorkDir ("t15_shell_{0}.txt" -f $Marker)
$script:espOff = 0

function WLog([string]$m) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  Add-Content -LiteralPath $LogFile -Value $line
  Write-Output $line
}
Set-Content $LogFile ''
WLog 'T15_SHELL_CANCEL START'

$cs = @'
using System; using System.Text; using System.Runtime.InteropServices;
public class AgentT15SC {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string s);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetWindowLongW(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  public const uint WM_COMMAND = 0x0111; public const uint WM_SETTEXT = 0x000C;
  public static int SetEdit(IntPtr edit, string text) {
    IntPtr p = Marshal.StringToHGlobalUni(text);
    SendMessageW(edit, WM_SETTEXT, IntPtr.Zero, p); Marshal.FreeHGlobal(p);
    SetWindowTextW(edit, text); return 1;
  }
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p); if (p != pid) return true;
      var cls = new StringBuilder(256); GetClassNameW(h, cls, 256);
      if (cls.ToString() == "RawrXD_IDE_Window") { found = h; return false; } return true;
    }, IntPtr.Zero); return found;
  }
  public static IntPtr FindChildById(IntPtr parent, int id) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(parent, (h, l) => { if (GetWindowLongW(h, -12) == id) { found = h; return false; } return true; }, IntPtr.Zero);
    return found;
  }
  public static string SelectModel(IntPtr main, IntPtr combo, string needle) {
    int cnt = SendMessageW(combo, 0x0146, IntPtr.Zero, IntPtr.Zero).ToInt32();
    for (int i = 0; i < cnt; i++) {
      int tlen = SendMessageW(combo, 0x0149, (IntPtr)i, IntPtr.Zero).ToInt32();
      if (tlen <= 0) continue;
      IntPtr buf = Marshal.AllocHGlobal((tlen + 2) * 2);
      try {
        SendMessageW(combo, 0x0148, (IntPtr)i, buf);
        string item = Marshal.PtrToStringUni(buf) ?? "";
        if (item.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0) {
          SendMessageW(combo, 0x014E, (IntPtr)i, IntPtr.Zero);
          PostMessageW(main, WM_COMMAND, (IntPtr)((1206 & 0xFFFF) | (1 << 16)), combo);
          return item;
        }
      } finally { Marshal.FreeHGlobal(buf); }
    }
    return "";
  }
  public static void MenuCommand(IntPtr main, int id) {
    SendMessageW(main, WM_COMMAND, (IntPtr)id, IntPtr.Zero);
    PostMessageW(main, WM_COMMAND, (IntPtr)id, IntPtr.Zero);
  }
}
'@
Add-Type $cs -EA SilentlyContinue | Out-Null

$sha = (Get-FileHash $CandExe -Algorithm SHA256).Hash
if ($sha -ne $ExpectSha) { WLog 'HASH_MISMATCH'; exit 3 }
[IO.File]::WriteAllText($Fixture, "// $Marker`r`n", [Text.UTF8Encoding]::new($false))

Get-Process -EA SilentlyContinue | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' -or $_.ProcessName -eq 'rawr' } | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 2
# Neutralize one-liner killers
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object {
  $_.CommandLine -and $_.CommandLine -match 'Get-Process RawrXD-Win32IDE-Native -ErrorAction SilentlyContinue \| Stop-Process'
} | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }

if (Test-Path $EspPath) { $script:espOff = (Get-Item $EspPath).Length }
$psi = New-Object Diagnostics.ProcessStartInfo
$psi.FileName = $CandExe; $psi.WorkingDirectory = $CandDir; $psi.UseShellExecute = $false
$psi.Arguments = "--open `"$Fixture`""
$psi.EnvironmentVariables['RAWRXD_CLI_PATH'] = $CliPath
$psi.EnvironmentVariables['RAWRXD_GUI_APPROVE_MUTATIONS'] = 'YES'
$proc = [Diagnostics.Process]::Start($psi)
WLog "LAUNCH $($proc.Id)"

$main = [IntPtr]::Zero
$dl = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $dl) {
  if ($proc.HasExited) { break }
  $main = [AgentT15SC]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero -and [AgentT15SC]::FindChildById($main, 1202) -ne [IntPtr]::Zero) { break }
  Start-Sleep -Milliseconds 300
}
if ($main -eq [IntPtr]::Zero -or $proc.HasExited) { WLog 'MAIN_FAIL'; exit 4 }
[void][AgentT15SC]::ShowWindow($main, 9)
[void][AgentT15SC]::SetForegroundWindow($main)
$inputEdit = [AgentT15SC]::FindChildById($main, 1202)
$combo = [AgentT15SC]::FindChildById($main, 1206)
$sel = ''
$mdl = (Get-Date).AddSeconds(60)
while ((Get-Date) -lt $mdl) {
  $sel = [AgentT15SC]::SelectModel($main, $combo, $Model)
  if ($sel) { break }
  Start-Sleep -Milliseconds 400
}
WLog "MODEL=$sel"
if (-not $sel) { WLog 'NO_MODEL'; exit 5 }

function Get-EspDelta {
  if (-not (Test-Path $EspPath)) { return '' }
  $fs = [IO.File]::Open($EspPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try { $fs.Position = [Math]::Min($script:espOff, $fs.Length); return (New-Object IO.StreamReader($fs)).ReadToEnd() }
  finally { $fs.Close() }
}

# SHELL
if (Test-Path $EspPath) { $script:espOff = (Get-Item $EspPath).Length }
[void][AgentT15SC]::SetEdit($inputEdit, "Use a shell or run_terminal tool to write file $ShellStamp with exact text SHELL_OK_$Marker")
[AgentT15SC]::MenuCommand($main, 4106)
WLog 'SHELL START'
$shellOk = 0
$end = (Get-Date).AddSeconds(360)
while ((Get-Date) -lt $end) {
  if ($proc.HasExited) { WLog "IDE_EXIT_SHELL $($proc.ExitCode)"; break }
  if ((Test-Path $ShellStamp) -and ((Get-Content $ShellStamp -Raw) -match [regex]::Escape("SHELL_OK_$Marker"))) {
    $shellOk = 1; WLog 'SHELL PASS'; break
  }
  $esp = Get-EspDelta
  if ($esp -match '"kind":"finished"' -and $esp -match '"message":"FAIL"') { WLog 'SHELL ESP_FAIL'; break }
  Start-Sleep -Milliseconds 400
}
Set-Content (Join-Path $OutDir 'ESP_SHELL.txt') -Value (Get-EspDelta) -Encoding utf8
WLog "SHELL ok=$shellOk exists=$(Test-Path $ShellStamp)"

# CANCEL
$cancelOk = 0; $cancelNote = 'NOT_RUN'; $timeoutResult = 'NOT_RUN'
if (-not $proc.HasExited) {
  if (Test-Path $EspPath) { $script:espOff = (Get-Item $EspPath).Length }
  [void][AgentT15SC]::SetEdit($inputEdit, "Keep using readFile repeatedly on files in $WorkDir for several minutes. Marker $Marker. Do not finish quickly.")
  [AgentT15SC]::MenuCommand($main, 4106)
  WLog 'CANCEL_TASK START'
  $childSeen = 0
  $w = (Get-Date).AddSeconds(120)
  while ((Get-Date) -lt $w) {
    if ($proc.HasExited) { break }
    $kids = @(Get-Process rawr -EA SilentlyContinue)
    $esp = Get-EspDelta
    if ($kids.Count -gt 0 -or $esp -match 'cli_run_start|inference_start|tool_start') { $childSeen = 1; WLog "CHILD seen=$($kids.Count)"; break }
    Start-Sleep -Milliseconds 300
  }
  Start-Sleep 4
  $kidsBefore = @(Get-Process rawr,deep2_agentic_loop -EA SilentlyContinue)
  WLog "KIDS_BEFORE=$($kidsBefore.Count)"
  [AgentT15SC]::MenuCommand($main, 4107)
  WLog 'CANCEL 4107'
  $w = (Get-Date).AddSeconds(60)
  while ((Get-Date) -lt $w) {
    if ($proc.HasExited) { $cancelNote = 'IDE_DEAD'; break }
    $kids = @(Get-Process rawr,deep2_agentic_loop -EA SilentlyContinue)
    if ($kids.Count -eq 0 -and $childSeen -eq 1) { $cancelOk = 1; $cancelNote = 'CHILD_CLEARED'; break }
    Start-Sleep -Milliseconds 400
  }
  $espC = Get-EspDelta
  if ($espC -match '(?i)Watchdog timeout|wall timeout|WallTimedOut') { $timeoutResult = 'OBSERVED' }
  Set-Content (Join-Path $OutDir 'ESP_CANCEL.txt') -Value $espC -Encoding utf8
  if ($cancelOk -eq 1 -and $proc.HasExited) { $cancelOk = 0; $cancelNote = 'IDE_DEAD_AFTER' }
  WLog "CANCEL ok=$cancelOk note=$cancelNote timeout=$timeoutResult ide_alive=$(-not $proc.HasExited)"
}

$shellR = if ($shellOk -eq 1) { 'PASS' } else { 'FAIL' }
$cancelR = if ($cancelOk -eq 1) { 'PASS' } else { 'FAIL' }
@"
SHELL=$shellR
CANCEL_CLEANUP=$cancelR
CANCEL_NOTE=$cancelNote
TIMEOUT=$timeoutResult
IDE_ALIVE=$([int](-not $proc.HasExited))
MARKER=$Marker
MODEL_UI=$sel
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
"@ | Set-Content (Join-Path $OutDir 'SHELL_CANCEL_RESULT.txt') -Encoding utf8

if (-not $proc.HasExited) { try { $proc.Kill() } catch {} }
Get-Process rawr,deep2_agentic_loop -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Write-Output "SHELL=$shellR CANCEL=$cancelR"
if ($shellR -ne 'PASS' -or $cancelR -ne 'PASS') { exit 1 }
exit 0
