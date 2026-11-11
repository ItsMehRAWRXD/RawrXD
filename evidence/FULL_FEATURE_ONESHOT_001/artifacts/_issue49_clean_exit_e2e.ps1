#Requires -Version 5.1
# Issue #49 map #9 ? Clean exit (no orphan workers) on tip_integ_candidate_001 (4CFB85B3).
# Dedicated proof ? map8 ORPHANS line. PROMOTE=0 MATURITY=82 E6CF HELD; NO_CROSS_SHA_PASS.
$ErrorActionPreference = 'Continue'
$ExpectSha = '5A34B393ECF7380576CE718C688DC4006C0E3B01090BB4DCD8B844FB594D1619'
$EvidenceRoot = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001'
$TipExe = Join-Path $EvidenceRoot 'package\tip_integ_candidate_001\RawrXD-Win32IDE-Native-Ext.exe'
$PkgDir = Split-Path $TipExe -Parent
$CandDir = Join-Path $EvidenceRoot 'candidates\tip_integ_candidate_001'
$OutDir = Join-Path $EvidenceRoot 'artifacts'
$ExtFixture = Join-Path $EvidenceRoot 'fixtures\ext_hello'
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$RunId = "integ_map9_run_$Stamp"
$Sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
if ($Sha -ne $ExpectSha) { Write-Host "SHA_DRIFT=$Sha expected=$ExpectSha"; exit 9 }

Add-Type @"
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class Map9CE {
  public const uint WM_SETTEXT=0x000C, WM_COMMAND=0x0111, WM_CLOSE=0x0010;
  public const uint CB_SETCURSEL=0x014E; public const int CBN_SELCHANGE=1;
  public const int ID_CHAT=1202, ID_SEND=1204, ID_MODEL=1206, ID_CTX=1220, ID_TOK=1219;
  public const int IDM_AGENTIC_LOOP_RUN=4106, IDM_AGENTIC_LOOP_CANCEL=4107;
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string s);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h,l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid || !IsWindowVisible(h)) return true;
      var sb = new StringBuilder(128); GetClassNameW(h, sb, sb.Capacity);
      if (sb.ToString().IndexOf("RawrXD") >= 0) { found = h; return false; }
      return true;
    }, IntPtr.Zero); return found;
  }
  public static IntPtr FindCtrl(IntPtr root, int id) {
    var stack = new Stack<IntPtr>(); stack.Push(root);
    while (stack.Count > 0) {
      IntPtr cur = stack.Pop(); var kids = new List<IntPtr>();
      EnumChildWindows(cur, (h,lp) => { kids.Add(h); return true; }, IntPtr.Zero);
      foreach (var k in kids) { if (GetDlgCtrlID(k) == id) return k; stack.Push(k); }
    } return IntPtr.Zero;
  }
  public static void SetText(IntPtr h, string t) { SendMessageW(h, WM_SETTEXT, IntPtr.Zero, t ?? ""); }
  public static string ComboText(IntPtr combo, int index) {
    int len = (int)SendMessageW(combo, 0x0149, (IntPtr)index, IntPtr.Zero);
    if (len <= 0) return "";
    var sb = new StringBuilder(len + 8);
    SendMessageW(combo, 0x0148, (IntPtr)index, sb); return sb.ToString();
  }
  public static int SelectModelContaining(IntPtr main, IntPtr combo, string needle) {
    if (combo == IntPtr.Zero) return -1;
    int count = (int)SendMessageW(combo, 0x0146, IntPtr.Zero, IntPtr.Zero);
    for (int i = 0; i < count; i++) {
      string t = ComboText(combo, i);
      if (t.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0) {
        SendMessageW(combo, CB_SETCURSEL, (IntPtr)i, IntPtr.Zero);
        SendMessageW(main, WM_COMMAND, (IntPtr)((CBN_SELCHANGE << 16) | (ID_MODEL & 0xFFFF)), combo);
        return i;
      }
    }
    return -1;
  }
  public static bool CloseClean(IntPtr main, int waitMs) {
    if (main == IntPtr.Zero || !IsWindow(main)) return true;
    PostMessageW(main, WM_CLOSE, IntPtr.Zero, IntPtr.Zero);
    int slept = 0;
    while (slept < waitMs) {
      if (!IsWindow(main)) return true;
      System.Threading.Thread.Sleep(250); slept += 250;
    }
    return !IsWindow(main);
  }
}
"@

function Get-DescendantSnapshot([int]$rootPid) {
  $all = @(Get-CimInstance Win32_Process | Select-Object ProcessId, ParentProcessId, Name)
  $byParent = @{}
  foreach ($row in $all) {
    $pp = [int]$row.ParentProcessId
    if (-not $byParent.ContainsKey($pp)) { $byParent[$pp] = New-Object System.Collections.Generic.List[object] }
    $byParent[$pp].Add($row)
  }
  $acc = New-Object System.Collections.Generic.List[object]
  $q = New-Object System.Collections.Generic.Queue[int]
  $q.Enqueue($rootPid)
  $seen = @{}
  while ($q.Count -gt 0) {
    $cur = $q.Dequeue()
    if ($seen.ContainsKey($cur)) { continue }
    $seen[$cur] = $true
    if ($byParent.ContainsKey($cur)) {
      foreach ($c in $byParent[$cur]) {
        $acc.Add($c)
        $q.Enqueue([int]$c.ProcessId)
      }
    }
  }
  return @($acc.ToArray())
}
function Format-Tree([object[]]$rows) {
  if (-not $rows -or $rows.Count -eq 0) { return '(none)' }
  ($rows | ForEach-Object { "  PID=$($_.ProcessId) PPID=$($_.ParentProcessId) NAME=$($_.Name)" }) -join "`n"
}
function Wait-Main($proc, [int]$sec) {
  $deadline = (Get-Date).AddSeconds($sec)
  while ((Get-Date) -lt $deadline) {
    try { $proc.Refresh() } catch {}
    if ($proc.HasExited) { return [IntPtr]::Zero }
    $h = [Map9CE]::FindMain([uint32]$proc.Id)
    if ($h -ne [IntPtr]::Zero) { return $h }
    Start-Sleep -Milliseconds 250
  }
  return [IntPtr]::Zero
}
function Wait-ProcessExit($proc, [int]$sec) {
  $deadline = (Get-Date).AddSeconds($sec)
  while ((Get-Date) -lt $deadline) {
    try { $proc.Refresh() } catch { return $true }
    if ($proc.HasExited) { return $true }
    Start-Sleep -Milliseconds 250
  }
  try { $proc.Refresh(); return [bool]$proc.HasExited } catch { return $true }
}

New-Item -ItemType Directory -Force -Path $OutDir,$CandDir | Out-Null
if (Test-Path (Join-Path $PkgDir 'deep2_agentic_loop.exe')) {
  Copy-Item -Force (Join-Path $PkgDir 'deep2_agentic_loop.exe') (Join-Path $CandDir 'deep2_agentic_loop.exe') -ErrorAction SilentlyContinue
}
Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop','rawr' -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 2

$runDir = Join-Path $CandDir ("map9_clean_exit_$Stamp")
$ws = Join-Path $runDir 'workspace'
New-Item -ItemType Directory -Force -Path $ws | Out-Null
$seed = Join-Path $ws "map9_seed_$Stamp.txt"
Set-Content -Path $seed -Encoding ascii -Value "MAP9_CLEAN_EXIT_SEED_$Stamp"
# deep2 ollama path defaults target calc.cpp ??? seed it in workspace + tip cwd.
Set-Content -Path (Join-Path $ws 'calc.cpp') -Encoding ascii -Value "int main(){return 0;}`n"
Set-Content -Path (Join-Path $PkgDir 'calc.cpp') -Encoding ascii -Value "int main(){return 0;}`n"
$journal = Join-Path $OutDir 'ISSUE49_CLEAN_EXIT_JOURNAL.txt'
$j = New-Object System.Collections.Generic.List[string]
function J([string]$m) { $line = "$(Get-Date -Format o) $m"; $j.Add($line); Write-Host $line }

$env:RAWRXD_GUI_APPROVE_MUTATIONS = 'YES'
$env:RAWRXD_DISCARD_UNSAVED_ON_CLOSE = '1'
# Force agentic child to deep2 (not checkout rawr.exe) so Map9 measures the
# orphan class named in ISSUE49_CLEAN_EXIT_RECEIPT.
$env:RAWRXD_CLI_PATH = (Join-Path $PkgDir 'deep2_agentic_loop.exe')
$env:RAWRXD_AGENTIC_FALLBACK_TASK = 'MAP9_CLEAN_EXIT list files in workspace'
$forceKill = 0; $exitCode = -1; $mainHex = '0x0'; $pidMain = 0
$treeBefore = @(); $treeActive = @(); $activity = @()
$orphansTree = @(); $orphansNamed = @()
$mainExited = $false; $hwndAliveAfter = $true; $map9 = 'FAIL'; $p1 = 'FAIL'
$deep2CancelGone = 'NA'; $argsLaunch = @()

J "RUN_ID=$RunId SHA=$Sha TIP=$TipExe"
# Map9 authority variant: chat+agentic, no --ext-dir (ext lifecycle is map8).
$argsLaunch = @($seed)
$activity += 'VARIANT=chat_plus_agentic_no_ext_dir'
$p = Start-Process -FilePath $TipExe -ArgumentList $argsLaunch -WorkingDirectory $ws -PassThru -WindowStyle Normal
$pidMain = $p.Id
J "LAUNCH_PID=$pidMain ARGS=$($argsLaunch -join ' ')"
$main = Wait-Main $p 55
if ($main -ne [IntPtr]::Zero -and -not $p.HasExited) {
  $p1 = 'PASS'
  $mainHex = ('0x{0:X}' -f $main.ToInt64())
  J "MAIN_HWND=$mainHex"
  Start-Sleep 4
  [void][Map9CE]::SetForegroundWindow($main)
  $treeBefore = @(Get-DescendantSnapshot $pidMain)
  J "TREE_BEFORE_COUNT=$($treeBefore.Count)"; J ("TREE_BEFORE`n" + (Format-Tree $treeBefore))

  $chat = [Map9CE]::FindCtrl($main, [Map9CE]::ID_CHAT)
  $send = [Map9CE]::FindCtrl($main, [Map9CE]::ID_SEND)
  $model = [Map9CE]::FindCtrl($main, [Map9CE]::ID_MODEL)
  $ctx = [Map9CE]::FindCtrl($main, [Map9CE]::ID_CTX)
  $tok = [Map9CE]::FindCtrl($main, [Map9CE]::ID_TOK)
  if ($ctx -ne [IntPtr]::Zero) {
    [void][Map9CE]::SendMessageW($ctx, [Map9CE]::CB_SETCURSEL, [IntPtr]0, [IntPtr]::Zero)
    [void][Map9CE]::SendMessageW($main, [Map9CE]::WM_COMMAND, [IntPtr]((1 -shl 16) -bor 1220), $ctx)
  }
  if ($tok -ne [IntPtr]::Zero) {
    [void][Map9CE]::SendMessageW($tok, [Map9CE]::CB_SETCURSEL, [IntPtr]0, [IntPtr]::Zero)
    [void][Map9CE]::SendMessageW($main, [Map9CE]::WM_COMMAND, [IntPtr]((1 -shl 16) -bor 1219), $tok)
  }
  $mi = [Map9CE]::SelectModelContaining($main, $model, 'llama3.2')
  if ($mi -lt 0) { $mi = [Map9CE]::SelectModelContaining($main, $model, 'llama3.1') }
  if ($mi -lt 0) { $mi = [Map9CE]::SelectModelContaining($main, $model, 'gemma3') }
  if ($chat -ne [IntPtr]::Zero -and $send -ne [IntPtr]::Zero) {
    [Map9CE]::SetText($chat, "MAP9_CLEAN_EXIT_$Stamp reply one word: ok")
    Start-Sleep -Milliseconds 200
    [void][Map9CE]::SendMessageW($main, [Map9CE]::WM_COMMAND, [IntPtr]1204, $send)
    $activity += 'CHAT_SEND=1'; Start-Sleep 4
  } else { $activity += 'CHAT_SEND=0' }

  # Chat-send clears the input; re-arm task text so agentic does not no-op.
  if ($chat -ne [IntPtr]::Zero) {
    [Map9CE]::SetText($chat, "MAP9_AGENTIC_$Stamp list files in workspace")
  }
  [void][Map9CE]::PostMessageW($main, [Map9CE]::WM_COMMAND, [IntPtr][Map9CE]::IDM_AGENTIC_LOOP_RUN, [IntPtr]::Zero)
  $activity += 'AGENTIC_RUN=1'; $activity += 'EXT_ARGV=0'
  # Wait for deep2 spawn (startup recovery may take several seconds).
  $deep2During = @()
  $spawnDeadline = (Get-Date).AddSeconds(25)
  while ((Get-Date) -lt $spawnDeadline) {
    $deep2During = @(Get-CimInstance Win32_Process -Filter "Name = 'deep2_agentic_loop.exe'" -EA SilentlyContinue)
    if ($deep2During.Count -gt 0) { break }
    Start-Sleep -Milliseconds 500
  }
  $treeActive = @(Get-DescendantSnapshot $pidMain)
  $deep2SeenIds = @($deep2During | ForEach-Object { [int]$_.ProcessId })
  if ($deep2SeenIds.Count -eq 0) {
    $deep2SeenIds = @($treeActive | Where-Object { $_.Name -match 'deep2_agentic_loop' } | ForEach-Object { [int]$_.ProcessId })
  }
  $deep2SeenCount = @($deep2SeenIds).Count
  J "TREE_ACTIVE_COUNT=$($treeActive.Count)"; J ("TREE_ACTIVE`n" + (Format-Tree $treeActive))
  J "DEEP2_DURING=$deep2SeenCount ids=$($deep2SeenIds -join ',')"
  $activity += "WORKERS_SEEN=$($treeActive.Count)"; $activity += "DEEP2_SEEN=$deep2SeenCount"

  # Quiesce agentic before quit (product cancel path); poll — do not force-kill deep2 here.
  [void][Map9CE]::PostMessageW($main, [Map9CE]::WM_COMMAND, [IntPtr][Map9CE]::IDM_AGENTIC_LOOP_CANCEL, [IntPtr]::Zero)
  $cancelDeadline = (Get-Date).AddSeconds(20)
  $deep2CancelGone = 'STILL_ALIVE'
  while ((Get-Date) -lt $cancelDeadline) {
    $left = @(Get-CimInstance Win32_Process -Filter "Name = 'deep2_agentic_loop.exe'" -EA SilentlyContinue)
    if ($left.Count -eq 0) { $deep2CancelGone = 'GONE'; break }
    Start-Sleep -Milliseconds 500
  }
  J "DEEP2_AFTER_CANCEL=$deep2CancelGone"
  $activity += "DEEP2_AFTER_CANCEL=$deep2CancelGone"

  $trackedIds = @($pidMain) + @($treeActive | ForEach-Object { [int]$_.ProcessId }) + @($deep2SeenIds)
  $trackedIds = @($trackedIds | Select-Object -Unique)

  # Chat stop if still streaming (best-effort; ID_STOP=1210)
  [void][Map9CE]::PostMessageW($main, [Map9CE]::WM_COMMAND, [IntPtr]1210, [IntPtr]::Zero)
  Start-Sleep 1

  $closed = [Map9CE]::CloseClean($main, 30000)
  $exited = Wait-ProcessExit $p 20
  if ($closed -and $exited) { $forceKill = 0; $mainExited = $true }
  else {
    $forceKill = 1
    try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } } catch {}
    Wait-ProcessExit $p 8 | Out-Null
    $mainExited = $p.HasExited
  }
  try { $exitCode = $p.ExitCode } catch { $exitCode = -1 }
  $hwndAliveAfter = [Map9CE]::IsWindow($main)
  Start-Sleep 5

  foreach ($tid in $trackedIds) {
    try {
      $alive = Get-Process -Id $tid -ErrorAction Stop
      if ($alive) { $orphansTree += [pscustomobject]@{ ProcessId=$tid; Name=$alive.ProcessName } }
    } catch {}
  }
  $orphansNamed = @(Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop','rawr' -ErrorAction SilentlyContinue)
  J "FORCE_KILL=$forceKill MAIN_EXITED=$mainExited EXIT=$exitCode HWND_AFTER=$hwndAliveAfter"
  J "ORPHANS_TREE=$($orphansTree.Count) ORPHANS_NAMED=$($orphansNamed.Count)"
  if ($orphansTree.Count -gt 0) { J ("ORPHAN_TREE_DETAIL`n" + (($orphansTree | ForEach-Object { "  PID=$($_.ProcessId) NAME=$($_.Name)" }) -join "`n")) }
  if ($orphansNamed.Count -gt 0) { J ("ORPHAN_NAMED_DETAIL`n" + (($orphansNamed | ForEach-Object { "  PID=$($_.Id) NAME=$($_.ProcessName)" }) -join "`n")) }

  $orphanCount = $orphansTree.Count + $orphansNamed.Count
  # Fail-closed: Map9 orphan class requires deep2 was actually exercised.
  if ($Sha -eq $ExpectSha -and $p1 -eq 'PASS' -and $forceKill -eq 0 -and $mainExited -and ($hwndAliveAfter -eq $false) -and $orphanCount -eq 0 -and $deep2SeenCount -gt 0 -and $deep2CancelGone -eq 'GONE') {
    $map9 = 'PASS'
  } else {
    $map9 = 'FAIL'
    J "MAP9_GATE sha=$($Sha -eq $ExpectSha) p1=$p1 fk=$forceKill exited=$mainExited hwndAlive=$hwndAliveAfter orphans=$orphanCount deep2Seen=$deep2SeenCount cancel=$deep2CancelGone"
  }
} else {
  $map9 = 'FAIL'
  try { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {}
  J 'FAIL_NO_HWND'
}

Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop' -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue
$j | Set-Content -Encoding ascii $journal
$orphanTotal = @($orphansTree).Count + @($orphansNamed).Count
$receipt = Join-Path $OutDir 'ISSUE49_CLEAN_EXIT_RECEIPT.txt'
@"
ISSUE49_CLEAN_EXIT_RECEIPT
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
ACTIVE_TRACK=ISSUE_49
MAP=9
CANDIDATE=tip_integ_candidate_001
TIP_SHA256=$Sha
TIP_EXE=$TipExe
SUITE_STAMP=$Stamp
RUN_ID=$RunId
MAIN_HWND=$mainHex
PID_MAIN=$pidMain
HARNESS=artifacts\_issue49_clean_exit_e2e.ps1
JOURNAL=$journal
RUN_DIR=$runDir
ACTIVITY=$($activity -join ';')
NO_CROSS_SHA_PASS=1
MAP8_ORPHANS_NE_MAP9=1
PROMOTE=0
MATURITY=82
E6CF_RESTORE=HELD
TIP_MOVE_AUTHORIZED=0
CC79_UNREPLACED=1
A4F_IMMUTABLE=1

## SHA gate
SHA_VERIFY=$(if($Sha -eq $ExpectSha){'PASS'}else{'FAIL'})
EXPECTED=$ExpectSha
MEASURED=$Sha

## Launch / activity
P1_HWND=$p1
ARGS=$($argsLaunch -join ' ')
DEEP2_AFTER_CANCEL=$deep2CancelGone
TREE_BEFORE_COUNT=$(@($treeBefore).Count)
TREE_BEFORE=
$(Format-Tree $treeBefore)
TREE_ACTIVE_COUNT=$(@($treeActive).Count)
TREE_ACTIVE=
$(Format-Tree $treeActive)

## Clean exit (FORCE_KILL=0 required)
FORCE_KILL=$forceKill
MAIN_EXITED=$mainExited
EXIT_CODE=$exitCode
HWND_ALIVE_AFTER=$hwndAliveAfter
ORPHANS_TREE=$(@($orphansTree).Count)
ORPHANS_NAMED=$(@($orphansNamed).Count)
ORPHANS=$orphanTotal
ORPHAN_TREE_DETAIL=
$(if(@($orphansTree).Count -eq 0){'(none)'}else{($orphansTree | ForEach-Object { "  PID=$($_.ProcessId) NAME=$($_.Name)" }) -join "`n"})
ORPHAN_NAMED_DETAIL=
$(if(@($orphansNamed).Count -eq 0){'(none)'}else{($orphansNamed | ForEach-Object { "  PID=$($_.Id) NAME=$($_.ProcessName)" }) -join "`n"})

## Disposition
MAP9=$map9
CLEAN_EXIT=$(if($forceKill -eq 0 -and $mainExited){'PASS'}else{'FAIL'})
NO_ORPHANS=$(if($orphanTotal -eq 0){'PASS'}else{'FAIL'})
ISSUE49_ADVANCE=$(if($map9 -eq 'PASS'){'9/11'}else{'8/11'})
NEXT_GAP=$(if($map9 -eq 'PASS'){'Map #10 Repeated-use + failure-recovery checks on the same SHA'}else{'Map #9 Clean exit (no orphan workers) ? deep2/agent orphan or FORCE_KILL after product activity'})
PROMOTE=0
"@ | Set-Content -Encoding ascii $receipt
Write-Host "RECEIPT=$receipt"; Write-Host "MAP9=$map9"
exit $(if ($map9 -eq 'PASS') { 0 } else { 1 })
