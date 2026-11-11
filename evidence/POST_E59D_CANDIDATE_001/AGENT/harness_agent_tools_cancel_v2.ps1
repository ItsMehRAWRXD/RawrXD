#Requires -Version 5.1
# T15 v2 — ESP-delta fail-closed; Agentic cancel 4107; avoid Request-A Stop.
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\AGENT'
$WorkDir = Join-Path $OutDir 'workdir'
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$CandExe = 'F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe'
$CandDir = Split-Path $CandExe
$ExpectSha = '3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F'
$CliPath = 'F:\rawrxd\build_ide\bin-msvc\rawr.exe'
$EspPath = 'F:\rawrxd\.rawrxd\ledger\agent_esp.jsonl'
$LogFile = Join-Path $OutDir 'RUNLOG_V2.txt'
$Model = 'qwen3:8b'
$IDM_RUN = 4106
$IDM_CANCEL = 4107
$Marker = 'T15_' + [guid]::NewGuid().ToString('N').Substring(0, 10)
$Fixture = Join-Path $WorkDir ("t15_fixture_{0}.cpp" -f $Marker)
$EditTarget = Join-Path $WorkDir ("t15_edit_{0}.cpp" -f $Marker)
$ShellStamp = Join-Path $WorkDir ("t15_shell_{0}.txt" -f $Marker)
$script:espOff = 0

function WLog([string]$m) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  Add-Content -LiteralPath $LogFile -Value $line
  Write-Output $line
}
Set-Content -LiteralPath $LogFile -Value ''
WLog 'T15_V2 START FAIL_CLOSED_ESP_DELTA=1 AVOID_REQUEST_A_CANCEL=1'

$cs = @'
using System; using System.Text; using System.Runtime.InteropServices;
public class AgentT15V2 {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string s);
  [DllImport("user32.dll")] public static extern int GetWindowTextLengthW(IntPtr h);
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
    SetWindowTextW(edit, text); return GetWindowTextLengthW(edit);
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
Add-Type -TypeDefinition $cs -ErrorAction SilentlyContinue | Out-Null

$sha = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
if ($sha -ne $ExpectSha) { WLog 'HASH_MISMATCH'; exit 3 }
[IO.File]::WriteAllText($Fixture, "// $Marker`r`nint t15_add(int a,int b){return a+b;}`r`n", [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($EditTarget, "// EDIT_ME $Marker`r`nint before = 0;`r`n", [Text.UTF8Encoding]::new($false))
$fixtureLeaf = [IO.Path]::GetFileName($Fixture)
$editShaPre = (Get-FileHash $EditTarget -Algorithm SHA256).Hash
WLog "MARKER=$Marker FIXTURE=$fixtureLeaf"

Get-Process -EA SilentlyContinue | Where-Object {
  $_.ProcessName -like 'RawrXD-Win32IDE*' -or $_.ProcessName -eq 'rawr'
} | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 2
if (Test-Path $EspPath) { $script:espOff = (Get-Item $EspPath).Length }

$psi = New-Object Diagnostics.ProcessStartInfo
$psi.FileName = $CandExe; $psi.WorkingDirectory = $CandDir; $psi.UseShellExecute = $false
$psi.Arguments = "--open `"$Fixture`""
$psi.EnvironmentVariables['RAWRXD_CLI_PATH'] = $CliPath
$psi.EnvironmentVariables['RAWRXD_GUI_APPROVE_MUTATIONS'] = 'YES'
$proc = [Diagnostics.Process]::Start($psi)
WLog "LAUNCH pid=$($proc.Id) espOff=$($script:espOff)"

$main = [IntPtr]::Zero
$dl = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $dl) {
  if ($proc.HasExited) { WLog "EXIT_EARLY $($proc.ExitCode)"; break }
  $main = [AgentT15V2]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero -and [AgentT15V2]::FindChildById($main, 1202) -ne [IntPtr]::Zero) { break }
  Start-Sleep -Milliseconds 300
}
if ($main -eq [IntPtr]::Zero -or $proc.HasExited) { WLog 'MAIN_FAIL'; exit 4 }
[void][AgentT15V2]::ShowWindow($main, 9)
[void][AgentT15V2]::SetForegroundWindow($main)
$inputEdit = [AgentT15V2]::FindChildById($main, 1202)
$combo = [AgentT15V2]::FindChildById($main, 1206)

$sel = ''
$mdl = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $mdl) {
  if ($proc.HasExited) { break }
  $sel = [AgentT15V2]::SelectModel($main, $combo, $Model)
  if ($sel) { break }
  Start-Sleep -Milliseconds 500
}
WLog "MODEL_UI='$sel'"
if (-not $sel) { WLog 'MODEL_FAIL continue_anyway=0'; }

function Get-EspDelta {
  if (-not (Test-Path $EspPath)) { return '' }
  $fs = [IO.File]::Open($EspPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $fs.Position = [Math]::Min($script:espOff, $fs.Length)
    return (New-Object IO.StreamReader($fs)).ReadToEnd()
  } finally { $fs.Close() }
}

function Invoke-Task([string]$task, [string]$tag, [int]$sec, [scriptblock]$check) {
  if ($proc.HasExited) { return @{ ok = 0; esp = '' } }
  if (Test-Path $EspPath) { $script:espOff = (Get-Item $EspPath).Length }
  [void][AgentT15V2]::SetEdit($inputEdit, $task)
  Start-Sleep -Milliseconds 200
  [AgentT15V2]::MenuCommand($main, $IDM_RUN)
  WLog "$tag START"
  $esp = ''
  $end = (Get-Date).AddSeconds($sec)
  while ((Get-Date) -lt $end) {
    if ($proc.HasExited) { WLog "$tag IDE_EXIT=$($proc.ExitCode)"; break }
    $esp = Get-EspDelta
    if (& $check $esp) { WLog "$tag PASS"; return @{ ok = 1; esp = $esp } }
    if ($esp -match '"kind":"finished"' -and $esp -match '"message":"FAIL"') {
      Start-Sleep 1
      $esp = Get-EspDelta
      if (& $check $esp) { return @{ ok = 1; esp = $esp } }
      WLog "$tag FINISHED_FAIL"
      break
    }
    Start-Sleep -Milliseconds 400
  }
  $esp = Get-EspDelta
  Set-Content (Join-Path $OutDir "ESP_$tag.txt") -Value $esp -Encoding utf8
  return @{ ok = [int](& $check $esp); esp = $esp }
}

$read = Invoke-Task "Use readFile tool on $Fixture and quote marker $Marker from file contents." 'READ' 360 {
  param($esp)
  $hasS = $false; $hasP = $false
  foreach ($ln in ($esp -split "`n")) {
    if ($ln -match 'tool_start' -and $ln -match 'readFile' -and $ln -match [regex]::Escape($fixtureLeaf)) { $hasS = $true }
    if ($ln -match 'tool_result' -and $ln -match 'readFile' -and $ln -match 'status=PASS' -and $ln -match [regex]::Escape($fixtureLeaf)) { $hasP = $true }
  }
  return ($hasS -and $hasP)
}

$editNeedle = "T15_EDITED_$Marker"
$edit = Invoke-Task "Use writeFile or editFiles to edit $EditTarget so it contains $editNeedle and before = 1." 'EDIT' 420 {
  param($esp)
  if (-not (Test-Path $EditTarget)) { return $false }
  $cur = Get-Content $EditTarget -Raw -EA SilentlyContinue
  return ($cur -and $cur -match [regex]::Escape($editNeedle))
}
$editShaPost = if (Test-Path $EditTarget) { (Get-FileHash $EditTarget -Algorithm SHA256).Hash } else { 'MISSING' }
if (Test-Path $EditTarget) { Copy-Item $EditTarget (Join-Path $OutDir 'EDIT_POST.txt') -Force }

$shell = Invoke-Task "Use shell/run_terminal to create $ShellStamp with exact contents SHELL_OK_$Marker" 'SHELL' 360 {
  param($esp)
  if (-not (Test-Path $ShellStamp)) { return $false }
  $st = Get-Content $ShellStamp -Raw -EA SilentlyContinue
  return ($st -match [regex]::Escape("SHELL_OK_$Marker"))
}

$cancelOk = 0; $cancelNote = 'NOT_RUN'; $timeoutResult = 'NOT_RUN'
if (-not $proc.HasExited -and $sel) {
  if (Test-Path $EspPath) { $script:espOff = (Get-Item $EspPath).Length }
  [void][AgentT15V2]::SetEdit($inputEdit, "Slowly readFile many files under $WorkDir for a long time. Marker $Marker.")
  [AgentT15V2]::MenuCommand($main, $IDM_RUN)
  WLog 'CANCEL_TASK START'
  $childSeen = 0
  $w = (Get-Date).AddSeconds(90)
  while ((Get-Date) -lt $w) {
    if ($proc.HasExited) { break }
    $kids = @(Get-Process rawr -EA SilentlyContinue)
    $esp = Get-EspDelta
    if ($kids.Count -gt 0 -or $esp -match 'cli_run_start|inference_start') { $childSeen = 1; break }
    Start-Sleep -Milliseconds 300
  }
  Start-Sleep 3
  [AgentT15V2]::MenuCommand($main, $IDM_CANCEL)
  WLog 'CANCEL_ISSUED 4107'
  $w = (Get-Date).AddSeconds(60)
  while ((Get-Date) -lt $w) {
    if ($proc.HasExited) { $cancelNote = 'IDE_DEAD'; break }
    $kids = @(Get-Process -EA SilentlyContinue | Where-Object { $_.ProcessName -eq 'rawr' -or $_.ProcessName -eq 'deep2_agentic_loop' })
    if ($kids.Count -eq 0 -and $childSeen -eq 1) { $cancelOk = 1; $cancelNote = 'CHILD_CLEARED'; break }
    Start-Sleep -Milliseconds 400
  }
  $espC = Get-EspDelta
  if ($espC -match '(?i)Watchdog timeout|wall timeout|WallTimedOut') { $timeoutResult = 'OBSERVED' }
  Set-Content (Join-Path $OutDir 'ESP_CANCEL.txt') -Value $espC -Encoding utf8
  if ($cancelOk -eq 1 -and $proc.HasExited) { $cancelOk = 0; $cancelNote = 'IDE_DEAD_AFTER' }
  WLog "CANCEL ok=$cancelOk note=$cancelNote childSeen=$childSeen"
} else {
  $cancelNote = 'SKIPPED'
}

$ideAlive = -not $proc.HasExited
$postSha = (Get-FileHash $CandExe -Algorithm SHA256).Hash
$readR = if ($read.ok -eq 1) { 'PASS' } else { 'FAIL' }
$editR = if ($edit.ok -eq 1 -and $editShaPre -ne $editShaPost) { 'PASS' } else { 'FAIL' }
$shellR = if ($shell.ok -eq 1) { 'PASS' } else { 'FAIL' }
$cancelR = if ($cancelOk -eq 1) { 'PASS' } else { 'FAIL' }
$mand = ($readR -eq 'PASS' -and $cancelR -eq 'PASS')
$overall = if ($mand -and $editR -eq 'PASS' -and $shellR -eq 'PASS') { 'PASS' } elseif ($mand) { 'PARTIAL' } else { 'FAIL' }

@"
# T15 AGENT TOOLS + CANCEL RECEIPT

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
GATE=FINISH_25_T15
CERT_EXE=$CandExe
CERT_EXE_SHA=$ExpectSha
SHA_PRE=$sha
SHA_POST=$postSha
SHA_MATCH=$([int]($sha -eq $ExpectSha -and $postSha -eq $ExpectSha))
CLI_PATH=$CliPath
MODEL=$Model
MODEL_UI=$sel
MARKER=$Marker
AVOID_REQUEST_A_CANCEL=1
CANCEL_PATH=IDM_AGENTIC_LOOP_CANCEL_4107
CANCEL_NOTE=$cancelNote
READ_FILE=$readR
FILE_EDIT=$editR
EDIT_SHA_PRE=$editShaPre
EDIT_SHA_POST=$editShaPost
SHELL=$shellR
TIMEOUT=$timeoutResult
CANCEL_CLEANUP=$cancelR
IDE_ALIVE=$([int]$ideAlive)
RESULT=$overall
HARNESS=harness_agent_tools_cancel_v2.ps1
PRIOR_FALSE_POSITIVE_SUPERSEDED=1
REBUILD=HELD
PROMOTE=0
CERTIFIED=0
NOTE=ESP delta only. Request-A Stop not exercised (BATCH1 FAIL).
"@ | Set-Content (Join-Path $OutDir 'RECEIPT.md') -Encoding utf8
Copy-Item (Join-Path $OutDir 'RECEIPT.md') 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\PHASE3\T15_AGENT_TOOLS_RECEIPT.md' -Force

if (-not $proc.HasExited) { try { $proc.Kill() } catch {} }
Get-Process rawr,deep2_agentic_loop -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
WLog "RESULT=$overall READ=$readR EDIT=$editR SHELL=$shellR CANCEL=$cancelR"
Write-Output "T15_RESULT=$overall"
if ($overall -eq 'FAIL') { exit 1 }
exit 0
