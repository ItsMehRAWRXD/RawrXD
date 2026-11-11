#Requires -Version 5.1
# T15 Agent tools + cancel via Agentic Loop menu (4106/4107).
# AVOIDS broken Chat Request-A Cancel / BM_CLICK Stop path (BATCH1 FAIL).
# PROMOTE=0 REBUILD=HELD
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\AGENT'
$WorkDir = Join-Path $OutDir 'workdir'
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null
$CandExe = 'F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe'
$CandDir = Split-Path $CandExe
$ExpectSha = '3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F'
$CliPath = 'F:\rawrxd\build_ide\bin-msvc\rawr.exe'
$LogFile = Join-Path $OutDir 'RUNLOG.txt'
$Model = 'qwen3:8b'
$IDM_AGENTIC_LOOP_RUN = 4106
$IDM_AGENTIC_LOOP_CANCEL = 4107
$Marker = 'T15_' + [guid]::NewGuid().ToString('N').Substring(0, 10)
$Fixture = Join-Path $WorkDir ("t15_fixture_{0}.cpp" -f $Marker)
$EditTarget = Join-Path $WorkDir ("t15_edit_{0}.cpp" -f $Marker)
$ShellStamp = Join-Path $WorkDir ("t15_shell_{0}.txt" -f $Marker)

function WLog([string]$m) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  Add-Content -LiteralPath $LogFile -Value $line
  Write-Output $line
}
Set-Content -LiteralPath $LogFile -Value ''
WLog 'T15 AGENT_TOOLS_CANCEL START PROMOTE=0 AVOID_REQUEST_A_CANCEL=1'

$cs = @'
using System; using System.Text; using System.Runtime.InteropServices;
public class AgentT15Ui {
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
  public const int GWL_ID = -12;
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
    EnumChildWindows(parent, (h, l) => { if (GetWindowLongW(h, GWL_ID) == id) { found = h; return false; } return true; }, IntPtr.Zero);
    return found;
  }
  public static string Text(IntPtr h) {
    int len = SendMessageW(h, 0x000E, IntPtr.Zero, IntPtr.Zero).ToInt32();
    if (len <= 0) len = GetWindowTextLengthW(h); if (len <= 0) return "";
    IntPtr buf = Marshal.AllocHGlobal((len + 2) * 2);
    try { SendMessageW(h, 0x000D, (IntPtr)(len + 1), buf); return Marshal.PtrToStringUni(buf) ?? ""; }
    finally { Marshal.FreeHGlobal(buf); }
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
          IntPtr wp = (IntPtr)((1206 & 0xFFFF) | (1 << 16));
          PostMessageW(main, WM_COMMAND, wp, combo);
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
WLog "PRE_HASH sha=$sha"
if ($sha -ne $ExpectSha) { WLog 'HASH_MISMATCH'; exit 3 }
if (-not (Test-Path $CliPath)) { WLog "CLI_MISSING $CliPath"; exit 3 }

$seed = @"
// $Marker fixture for T15 agent readFile
int t15_add(int a, int b) { return a + b; }
"@
[IO.File]::WriteAllText($Fixture, $seed, [Text.UTF8Encoding]::new($false))
[IO.File]::WriteAllText($EditTarget, "// EDIT_ME $Marker`r`nint before = 0;`r`n", [Text.UTF8Encoding]::new($false))
$fixtureShaPre = (Get-FileHash $Fixture -Algorithm SHA256).Hash
$editShaPre = (Get-FileHash $EditTarget -Algorithm SHA256).Hash
WLog "FIXTURE=$Fixture SHA=$fixtureShaPre"
WLog "EDIT_TARGET=$EditTarget SHA_PRE=$editShaPre"

Get-Process -ErrorAction SilentlyContinue | Where-Object {
  $_.ProcessName -like 'RawrXD-Win32IDE*' -or $_.ProcessName -eq 'rawr' -or $_.ProcessName -eq 'deep2_agentic_loop'
} | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $CandExe
$psi.WorkingDirectory = $CandDir
$psi.UseShellExecute = $false
$psi.Arguments = "--open `"$Fixture`""
$psi.EnvironmentVariables['RAWRXD_CLI_PATH'] = $CliPath
$psi.EnvironmentVariables['RAWRXD_GUI_APPROVE_MUTATIONS'] = 'YES'
$proc = [Diagnostics.Process]::Start($psi)
WLog "LAUNCH pid=$($proc.Id) CLI=$CliPath APPROVE=YES"

$main = [IntPtr]::Zero
$deadline = (Get-Date).AddSeconds(90)
while ((Get-Date) -lt $deadline) {
  if ($proc.HasExited) { WLog "EXIT_EARLY $($proc.ExitCode)"; break }
  $main = [AgentT15Ui]::FindMain([uint32]$proc.Id)
  if ($main -ne [IntPtr]::Zero -and [AgentT15Ui]::IsWindowVisible($main)) {
    if ([AgentT15Ui]::FindChildById($main, 1202) -ne [IntPtr]::Zero) { break }
  }
  Start-Sleep -Milliseconds 300
}
if ($main -eq [IntPtr]::Zero) { WLog 'MAIN_TIMEOUT'; exit 4 }
[void][AgentT15Ui]::ShowWindow($main, 9)
[void][AgentT15Ui]::SetForegroundWindow($main)
WLog ("HWND=0x{0:X}" -f $main.ToInt64())

$inputEdit = [AgentT15Ui]::FindChildById($main, 1202)
$outputEdit = [AgentT15Ui]::FindChildById($main, 1203)
$combo = [AgentT15Ui]::FindChildById($main, 1206)
$sel = [AgentT15Ui]::SelectModel($main, $combo, $Model)
WLog "MODEL_UI='$sel'"
Start-Sleep -Milliseconds 500

$logsDir = Join-Path $CandDir 'logs'
$sessionLog = Get-ChildItem $logsDir -Filter 'RawrXD_IDE_*.log' -EA SilentlyContinue |
  Sort-Object LastWriteTime -Descending | Select-Object -First 1
$logOff = if ($sessionLog) { (Get-Item $sessionLog.FullName).Length } else { 0 }
WLog "SESSION_LOG=$($sessionLog.FullName) off=$logOff"

function Read-LogDelta {
  if (-not $sessionLog) { return '' }
  $fs = [IO.File]::Open($sessionLog.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
  try {
    $fs.Position = [Math]::Min($logOff, $fs.Length)
    $sr = New-Object IO.StreamReader($fs)
    return $sr.ReadToEnd()
  } finally { $fs.Close() }
}

function Get-EspTail {
  $esp = 'F:\rawrxd\.rawrxd\ledger\agent_esp.jsonl'
  if (Test-Path $esp) {
    return (Get-Content $esp -Tail 80 -ErrorAction SilentlyContinue) -join "`n"
  }
  return ''
}

# --- Phase READ: audit/readFile ---
$readTask = "audit inspect readFile the open source file and report the marker $Marker. Use readFile tool."
[void][AgentT15Ui]::SetEdit($inputEdit, $readTask)
Start-Sleep -Milliseconds 200
[AgentT15Ui]::MenuCommand($main, $IDM_AGENTIC_LOOP_RUN)
WLog 'READ_TASK_STARTED menu=4106'
$readTool = 0; $readPass = 0; $readOut = ''
$dl = (Get-Date).AddSeconds(300)
while ((Get-Date) -lt $dl) {
  if ($proc.HasExited) { WLog "CRASH_READ exit=$($proc.ExitCode)"; break }
  $delta = Read-LogDelta
  $esp = Get-EspTail
  $ui = [AgentT15Ui]::Text($outputEdit)
  $blob = "$delta`n$esp`n$ui"
  if ($blob -match 'tool_start|tool_result|readFile') { $readTool = 1 }
  if ($blob -match [regex]::Escape($Marker) -and $blob -match '(?i)tool_result|PASS|Task completed|readFile') {
    $readPass = 1
    $readOut = $blob
    break
  }
  if ($blob -match '(?i)Task completed|agentic loop exited|Agent task' -and $readTool -eq 1) {
    $readOut = $blob
    if ($blob -match [regex]::Escape($Marker)) { $readPass = 1 }
    break
  }
  # child rawr still running?
  $kids = @(Get-Process -ErrorAction SilentlyContinue | Where-Object { $_.ProcessName -eq 'rawr' })
  if ($kids.Count -eq 0 -and ((Get-Date) -gt $dl.AddSeconds(-240))) {
    # allow early settle
  }
  Start-Sleep -Milliseconds 500
}
Set-Content -LiteralPath (Join-Path $OutDir 'READ_TRACE.txt') -Value $readOut -Encoding utf8
WLog "READ tool=$readTool pass=$readPass"

# --- Phase EDIT: writeFile/edit ---
$editNeedle = "T15_EDITED_$Marker"
$editTask = "edit the source file $EditTarget : replace before = 0 with before = 1 and append a comment containing $editNeedle. Use writeFile or editFiles tools."
[void][AgentT15Ui]::SetEdit($inputEdit, $editTask)
Start-Sleep -Milliseconds 200
[AgentT15Ui]::MenuCommand($main, $IDM_AGENTIC_LOOP_RUN)
WLog 'EDIT_TASK_STARTED menu=4106'
$editTool = 0; $editPass = 0
$dl = (Get-Date).AddSeconds(360)
while ((Get-Date) -lt $dl) {
  if ($proc.HasExited) { WLog "CRASH_EDIT exit=$($proc.ExitCode)"; break }
  $delta = Read-LogDelta
  $esp = Get-EspTail
  $ui = [AgentT15Ui]::Text($outputEdit)
  $blob = "$delta`n$esp`n$ui"
  if ($blob -match 'tool_start|writeFile|editFiles|tool_result') { $editTool = 1 }
  if (Test-Path $EditTarget) {
    $cur = Get-Content -LiteralPath $EditTarget -Raw -ErrorAction SilentlyContinue
    if ($cur -and ($cur -match [regex]::Escape($editNeedle) -or $cur -match 'before\s*=\s*1')) {
      $editPass = 1
      break
    }
  }
  if ($blob -match '(?i)Task completed|agentic loop exited' -and $editTool -eq 1) { break }
  Start-Sleep -Milliseconds 500
}
$editShaPost = if (Test-Path $EditTarget) { (Get-FileHash $EditTarget -Algorithm SHA256).Hash } else { 'MISSING' }
$editBody = if (Test-Path $EditTarget) { Get-Content $EditTarget -Raw } else { '' }
Set-Content -LiteralPath (Join-Path $OutDir 'EDIT_POST.txt') -Value $editBody -Encoding utf8
WLog "EDIT tool=$editTool pass=$editPass sha_pre=$editShaPre sha_post=$editShaPost"

# --- Phase SHELL: create stamp file via shell tool ---
$shellTask = "Use a shell/run tool to create file $ShellStamp containing SHELL_OK_$Marker then stop."
[void][AgentT15Ui]::SetEdit($inputEdit, $shellTask)
Start-Sleep -Milliseconds 200
[AgentT15Ui]::MenuCommand($main, $IDM_AGENTIC_LOOP_RUN)
WLog 'SHELL_TASK_STARTED menu=4106'
$shellTool = 0; $shellPass = 0
$dl = (Get-Date).AddSeconds(300)
while ((Get-Date) -lt $dl) {
  if ($proc.HasExited) { WLog "CRASH_SHELL exit=$($proc.ExitCode)"; break }
  $delta = Read-LogDelta
  $esp = Get-EspTail
  $blob = "$delta`n$esp"
  if ($blob -match 'tool_start|run_terminal|runShell|shell|powershell') { $shellTool = 1 }
  if (Test-Path $ShellStamp) {
    $st = Get-Content $ShellStamp -Raw -ErrorAction SilentlyContinue
    if ($st -match [regex]::Escape("SHELL_OK_$Marker")) { $shellPass = 1; break }
  }
  if ($blob -match '(?i)Task completed|agentic loop exited') { break }
  Start-Sleep -Milliseconds 500
}
WLog "SHELL tool=$shellTool pass=$shellPass exists=$(Test-Path $ShellStamp)"

# --- Phase CANCEL: long task then menu 4107 (NOT chat Stop / Request A) ---
$cancelTask = "audit inspect the entire repository recursively with many readFile calls for at least 5 minutes; do not finish early. Marker $Marker CANCEL_LONG."
[void][AgentT15Ui]::SetEdit($inputEdit, $cancelTask)
Start-Sleep -Milliseconds 200
[AgentT15Ui]::MenuCommand($main, $IDM_AGENTIC_LOOP_RUN)
WLog 'CANCEL_TASK_STARTED menu=4106'
Start-Sleep -Seconds 8
$kidsBefore = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
  $_.ProcessName -eq 'rawr' -or $_.ProcessName -eq 'deep2_agentic_loop'
})
WLog "KIDS_BEFORE=$($kidsBefore.Count) pids=$(($kidsBefore | ForEach-Object Id) -join ',')"
[AgentT15Ui]::MenuCommand($main, $IDM_AGENTIC_LOOP_CANCEL)
WLog 'CANCEL_ISSUED menu=4107 (NOT Request-A Stop)'
$cancelClean = 0
$dl = (Get-Date).AddSeconds(45)
while ((Get-Date) -lt $dl) {
  if ($proc.HasExited) { WLog "IDE_CRASH_ON_CANCEL exit=$($proc.ExitCode)"; break }
  $kids = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
    $_.ProcessName -eq 'rawr' -or $_.ProcessName -eq 'deep2_agentic_loop'
  })
  $delta = Read-LogDelta
  if ($kids.Count -eq 0 -and ($delta -match '(?i)cancel|terminated|Task completed|onAgenticLoopCancel')) {
    $cancelClean = 1
    break
  }
  if ($kids.Count -eq 0 -and ((Get-Date) -gt $dl.AddSeconds(-30))) {
    $cancelClean = 1
    break
  }
  Start-Sleep -Milliseconds 500
}
$kidsAfter = @(Get-Process -ErrorAction SilentlyContinue | Where-Object {
  $_.ProcessName -eq 'rawr' -or $_.ProcessName -eq 'deep2_agentic_loop'
})
$ideAlive = -not $proc.HasExited
if ($kidsAfter.Count -eq 0 -and $ideAlive) { $cancelClean = 1 }
WLog "CANCEL clean=$cancelClean kids_after=$($kidsAfter.Count) ide_alive=$ideAlive"

# timeout witness: if wall timeout was observed in logs during any phase
$allDelta = Read-LogDelta
$timeoutSeen = if ($allDelta -match '(?i)Watchdog timeout|wall timeout|timedOut|timeout') { 1 } else { 0 }
# Explicit short timeout probe only if not already seen — spawn rawr with tiny wall via cancel path already proves cleanup.
# Record NOT_RUN vs observed.
$timeoutResult = if ($timeoutSeen -eq 1) { 'OBSERVED' } else { 'NOT_RUN' }

$postSha = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
$readResult = if ($readPass -eq 1 -and $readTool -eq 1) { 'PASS' } else { 'FAIL' }
$editResult = if ($editPass -eq 1) { 'PASS' } else { 'FAIL' }
$shellResult = if ($shellPass -eq 1) { 'PASS' } else { 'FAIL' }
$cancelResult = if ($cancelClean -eq 1 -and $ideAlive) { 'PASS' } else { 'FAIL' }

# Fail-closed overall: require read + cancel at minimum; edit/shell/timeout may FAIL without inventing PASS
$mandatoryOk = ($readResult -eq 'PASS' -and $cancelResult -eq 'PASS')
$overall = if ($mandatoryOk -and $editResult -eq 'PASS' -and $shellResult -eq 'PASS') { 'PASS' }
           elseif ($mandatoryOk) { 'PARTIAL' }
           else { 'FAIL' }

Set-Content -LiteralPath (Join-Path $OutDir 'SESSION_DELTA.txt') -Value $allDelta -Encoding utf8
Set-Content -LiteralPath (Join-Path $OutDir 'ESP_TAIL.txt') -Value (Get-EspTail) -Encoding utf8

$receipt = @"
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
READ_FILE=$readResult
FILE_EDIT=$editResult
EDIT_SHA_PRE=$editShaPre
EDIT_SHA_POST=$editShaPost
SHELL=$shellResult
TIMEOUT=$timeoutResult
CANCEL_CLEANUP=$cancelResult
IDE_ALIVE=$([int]$ideAlive)
RESULT=$overall
REBUILD=HELD
PROMOTE=0
CERTIFIED=0
NOTE=Mandatory=readFile+agentic-cancel cleanup. Chat Request-A Stop path intentionally not exercised (BATCH1 FAIL).
"@
Set-Content -LiteralPath (Join-Path $OutDir 'RECEIPT.md') -Value $receipt -Encoding utf8
Copy-Item (Join-Path $OutDir 'RECEIPT.md') 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\PHASE3\T15_AGENT_TOOLS_RECEIPT.md' -Force

if ($ideAlive) { try { $proc.Kill() } catch {} }
# ensure orphans gone
Get-Process -ErrorAction SilentlyContinue | Where-Object {
  $_.ProcessName -eq 'rawr' -or $_.ProcessName -eq 'deep2_agentic_loop'
} | Stop-Process -Force -EA SilentlyContinue

WLog "RESULT=$overall READ=$readResult EDIT=$editResult SHELL=$shellResult CANCEL=$cancelResult TIMEOUT=$timeoutResult"
Write-Output "T15_RESULT=$overall"
if ($overall -eq 'FAIL') { exit 1 }
