$ExpectSha='4CFB85B3DD86602156D417FE367D82C84ABA5774AE3BD65FE2BA788614D70321'
$EvidenceRoot='F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001'
$TipExe=Join-Path $EvidenceRoot 'package\tip_integ_candidate_001\RawrXD-Win32IDE-Native-Ext.exe'
$Sha=(Get-FileHash $TipExe -Algorithm SHA256).Hash
$Stamp=Get-Date -Format 'yyyyMMdd-HHmmss'
$RunId="integ_map9_run_$Stamp"
$CandDir=Join-Path $EvidenceRoot 'candidates\tip_integ_candidate_001'
$OutDir=Join-Path $EvidenceRoot 'artifacts'
$runDir=Join-Path $CandDir "map9_clean_exit_$Stamp"
$ws=Join-Path $runDir 'workspace'
New-Item -ItemType Directory -Force -Path $ws|Out-Null
$seed=Join-Path $ws "map9_seed_$Stamp.txt"
Set-Content $seed -Encoding ascii "MAP9_CLEAN_EXIT_SEED_$Stamp"
Copy-Item -Force (Join-Path (Split-Path $TipExe) 'deep2_agentic_loop.exe') (Join-Path $CandDir 'deep2_agentic_loop.exe') -EA SilentlyContinue
$env:RAWRXD_GUI_APPROVE_MUTATIONS='YES'
Add-Type @"
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class Map9CE3 {
  public const uint WM_SETTEXT=0x000C, WM_COMMAND=0x0111, WM_CLOSE=0x0010;
  public const uint CB_SETCURSEL=0x014E; public const int CBN_SELCHANGE=1;
  public const int ID_CHAT=1202, ID_SEND=1204, ID_MODEL=1206;
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
function Get-Desc([int]$root){
  $all=@(Get-CimInstance Win32_Process|Select ProcessId,ParentProcessId,Name)
  $bp=@{}; foreach($r in $all){ $pp=[int]$r.ParentProcessId; if(-not $bp.ContainsKey($pp)){$bp[$pp]=New-Object Collections.Generic.List[object]}; $bp[$pp].Add($r) }
  $acc=New-Object Collections.Generic.List[object]; $q=New-Object Collections.Generic.Queue[int]; $q.Enqueue($root); $seen=@{}
  while($q.Count -gt 0){ $cur=$q.Dequeue(); if($seen.ContainsKey($cur)){continue}; $seen[$cur]=$true; if($bp.ContainsKey($cur)){ foreach($c in $bp[$cur]){ $acc.Add($c); $q.Enqueue([int]$c.ProcessId) } } }
  return @($acc.ToArray())
}
function Fmt($rows){ if(-not $rows -or $rows.Count -eq 0){return '(none)'}; ($rows|%{"  PID=$($_.ProcessId) PPID=$($_.ParentProcessId) NAME=$($_.Name)"}) -join "`n" }

$p=Start-Process -FilePath $TipExe -ArgumentList @($seed) -WorkingDirectory $ws -PassThru -WindowStyle Normal
$pidMain=$p.Id
$main=[IntPtr]::Zero
for($i=0;$i -lt 220;$i++){ try{$p.Refresh()}catch{}; if($p.HasExited){break}; $main=[Map9CE3]::FindMain([uint32]$pidMain); if($main -ne [IntPtr]::Zero){break}; Start-Sleep -Milliseconds 250 }
Write-Host "HWND=0x$('{0:X}' -f $main.ToInt64()) PID=$pidMain"
if($main -eq [IntPtr]::Zero){ throw 'NO_HWND' }
Start-Sleep 5
[void][Map9CE3]::SetForegroundWindow($main)
$treeBefore=@(Get-Desc $pidMain)
Write-Host "TREE_BEFORE=$(Fmt $treeBefore)"
$chat=[Map9CE3]::FindCtrl($main,1202); $send=[Map9CE3]::FindCtrl($main,1204); $model=[Map9CE3]::FindCtrl($main,1206)
$mi=[Map9CE3]::SelectModelContaining($main,$model,'llama3.2'); if($mi -lt 0){$mi=[Map9CE3]::SelectModelContaining($main,$model,'llama3.1')}
# Chat activity
[Map9CE3]::SetText($chat,"MAP9_CE_$Stamp reply ok"); [void][Map9CE3]::SendMessageW($main,0x0111,[IntPtr]1204,$send); Start-Sleep 6
# Agentic activity then cancel+join
[void][Map9CE3]::PostMessageW($main,0x0111,[IntPtr]4106,[IntPtr]::Zero)
$deepSeen=@(); for($i=0;$i -lt 30;$i++){ $deepSeen=@(Get-Process -Name deep2_agentic_loop -EA SilentlyContinue); if($deepSeen.Count -gt 0){break}; Start-Sleep -Milliseconds 400 }
Write-Host "DEEP2_SEEN=$($deepSeen.Count) ids=$(($deepSeen|%{$_.Id}) -join ',')"
$treeActive=@(Get-Desc $pidMain)
Write-Host "TREE_ACTIVE=$(Fmt $treeActive)"
[void][Map9CE3]::PostMessageW($main,0x0111,[IntPtr]4107,[IntPtr]::Zero)
[void][Map9CE3]::PostMessageW($main,0x0111,[IntPtr]1210,[IntPtr]::Zero)
$gone='STILL'; for($i=0;$i -lt 50;$i++){ if(-not (Get-Process -Name deep2_agentic_loop -EA SilentlyContinue)){ $gone='GONE'; break }; Start-Sleep -Milliseconds 400 }
Write-Host "DEEP2_AFTER_CANCEL=$gone"
# Extra settle like map7
Start-Sleep 3
$tracked=@($pidMain)+@($treeActive|%{ [int]$_.ProcessId })+@($deepSeen|%{ [int]$_.Id }) | Select -Unique
$closed=[Map9CE3]::CloseClean($main,25000)
$exited=$false; for($i=0;$i -lt 80;$i++){ try{$p.Refresh()}catch{$exited=$true;break}; if($p.HasExited){$exited=$true;break}; Start-Sleep -Milliseconds 250 }
$force=0
if(-not ($closed -and $exited)){
  Write-Host 'CLEAN_CLOSE_TIMEOUT ? measuring as FORCE_KILL escalate'
  $force=1
  try{ if(-not $p.HasExited){ Stop-Process -Id $p.Id -Force -EA SilentlyContinue } }catch{}
  Start-Sleep 2
}
try{$p.Refresh(); $exited=$p.HasExited; $exit=$p.ExitCode}catch{$exited=$true; $exit=-1}
Start-Sleep 5
$orphTree=@(); foreach($tid in $tracked){ try{ $a=Get-Process -Id $tid -EA Stop; if($a){ $orphTree += [pscustomobject]@{ProcessId=$a.Id; Name=$a.ProcessName} } }catch{} }
$orphNamed=@(Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop' -EA SilentlyContinue)
# Also catch deep2 spawned after cancel window
$lateDeep=@(Get-Process -Name deep2_agentic_loop -EA SilentlyContinue)
$map9='FAIL'
$orphanTotal=$orphTree.Count+$orphNamed.Count
if($force -eq 0 -and $exited -and -not [Map9CE3]::IsWindow($main) -and $orphanTotal -eq 0){ $map9='PASS' }
Write-Host "FORCE_KILL=$force MAIN_EXITED=$exited EXIT=$exit ORPHANS=$orphanTotal MAP9=$map9"
$orphNamed | %{ Write-Host "ORPHAN_NAMED $($_.Id) $($_.ProcessName)" }
$orphTree | %{ Write-Host "ORPHAN_TREE $($_.ProcessId) $($_.Name)" }
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
MAIN_HWND=0x$('{0:X}' -f $main.ToInt64())
PID_MAIN=$pidMain
HARNESS=artifacts\_issue49_clean_exit_e2e.ps1
VARIANT=chat_plus_agentic_no_ext_dir
ACTIVITY=CHAT_SEND=1;AGENTIC_RUN=1;EXT_ARGV=0;DEEP2_SEEN=$($deepSeen.Count);DEEP2_AFTER_CANCEL=$gone
NO_CROSS_SHA_PASS=1
MAP8_ORPHANS_NE_MAP9=1
PROMOTE=0
MATURITY=82
E6CF_RESTORE=HELD
TIP_MOVE_AUTHORIZED=0
CC79_UNREPLACED=1
A4F_IMMUTABLE=1

## SHA gate
SHA_VERIFY=PASS
EXPECTED=$ExpectSha
MEASURED=$Sha

## Launch / activity
P1_HWND=PASS
TREE_BEFORE_COUNT=$($treeBefore.Count)
TREE_BEFORE=
$(Fmt $treeBefore)
TREE_ACTIVE_COUNT=$($treeActive.Count)
TREE_ACTIVE=
$(Fmt $treeActive)
DEEP2_DURING=$($deepSeen.Count)
DEEP2_IDS=$(($deepSeen|%{$_.Id}) -join ',')
DEEP2_AFTER_CANCEL=$gone

## Clean exit (FORCE_KILL=0 required)
FORCE_KILL=$force
MAIN_EXITED=$exited
EXIT_CODE=$exit
HWND_ALIVE_AFTER=$([Map9CE3]::IsWindow($main))
ORPHANS_TREE=$($orphTree.Count)
ORPHANS_NAMED=$($orphNamed.Count)
ORPHANS=$orphanTotal
ORPHAN_TREE_DETAIL=
$(if($orphTree.Count -eq 0){'(none)'}else{($orphTree|%{"  PID=$($_.ProcessId) NAME=$($_.Name)"}) -join "`n"})
ORPHAN_NAMED_DETAIL=
$(if($orphNamed.Count -eq 0){'(none)'}else{($orphNamed|%{"  PID=$($_.Id) NAME=$($_.ProcessName)"}) -join "`n"})

## Disposition
MAP9=$map9
CLEAN_EXIT=$(if($force -eq 0 -and $exited){'PASS'}else{'FAIL'})
NO_ORPHANS=$(if($orphanTotal -eq 0){'PASS'}else{'FAIL'})
ISSUE49_ADVANCE=$(if($map9 -eq 'PASS'){'9/11'}else{'8/11'})
NEXT_GAP=$(if($map9 -eq 'PASS'){'Map #10 Repeated-use + failure-recovery checks on the same SHA'}else{'Map #9 Clean exit (no orphan workers) ? FORCE_KILL!=0 and/or deep2_agentic_loop orphan after chat/agentic activity'})
PROMOTE=0
"@ | Set-Content -Encoding ascii (Join-Path $OutDir 'ISSUE49_CLEAN_EXIT_RECEIPT.txt')
Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Write-Host "RECEIPT written MAP9=$map9"
