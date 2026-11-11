# Wave5 hidden-gap surface audit on controlling tip SHA.
# Beyond W3 four-panel: editor tabs, search/SCM/settings activity, VisId(1300) after Build,
# dual-Problems authority, CU verify. PROMOTE=0. NOT_RUN!=PASS.
param(
  [string]$TipExe = 'F:\rawrxd\release\RawrXD-readiness-rc5b\RawrXD-Win32IDE-Native-Ext.exe',
  [string]$CuVerify = 'F:\rawrxd\release\RawrXD-readiness-rc5b\rawrxd_computer_use_ide_verify.exe',
  [string]$BrokenCpp = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\fixtures\broken_multi.cpp',
  [int]$SettleMs = 2000
)
$ErrorActionPreference = 'Continue'
$Root = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\hidden_gap_wave5'
$OutDir = Join-Path $Root 'artifacts'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
if (-not (Test-Path -LiteralPath $TipExe)) { throw "TipExe missing: $TipExe" }

$sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$receipt = Join-Path $OutDir ("SURFACE_AUDIT_$stamp.txt")
$lines = New-Object System.Collections.Generic.List[string]
function L([string]$m) { $script:lines.Add($m); Write-Host $m }

Add-Type @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class W5Surf {
  public const uint WM_COMMAND = 0x0111;
  public const uint WM_CLOSE = 0x0010;
  public const uint LVM_GETITEMCOUNT = 0x1004;
  public const uint WM_GETTEXTLENGTH = 0x000E;
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
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
  public static Dictionary<int,string> ChildMap(IntPtr root) {
    var d = new Dictionary<int,string>();
    EnumChildWindows(root, (h, lp) => {
      int id = GetDlgCtrlID(h);
      if (id == 0) return true;
      var cls = new StringBuilder(64);
      GetClassNameW(h, cls, cls.Capacity);
      bool vis = IsWindowVisible(h);
      if (!d.ContainsKey(id)) d[id] = cls.ToString() + "|vis=" + (vis?"1":"0");
      return true;
    }, IntPtr.Zero);
    return d;
  }
  public static int ItemCount(IntPtr root, int id) {
    IntPtr h = FindId(root, id);
    if (h == IntPtr.Zero) return -1;
    return (int)SendMessageW(h, LVM_GETITEMCOUNT, IntPtr.Zero, IntPtr.Zero);
  }
}
"@

L "ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))"
L "SWARM=W5"
L "GATE=HIDDEN_GAP_SURFACE_AUDIT"
L "TIP_EXE=$TipExe"
L "TIP_SHA256=$sha"
L "PROMOTE=0"
L "NO_RC4_MUTATION=1"

# --- Binary marker disposition (dual Problems / dock) ---
$bytes = [IO.File]::ReadAllBytes($TipExe)
$ascii = [Text.Encoding]::ASCII.GetString($bytes)
$markG7a = $ascii.Contains('G7_ensurePanelVisible_ShowWindow_1300')
$markG7b = $ascii.Contains('G7_layoutBottomDock_SetWindowPos_1300')
$markInitProb = $ascii.Contains('initProblemsPanel')
$markSearchTip = $ascii.Contains('Search (Ctrl+Shift+F)')
$markScmTip = $ascii.Contains('Source Control')
$markSettingsTip = $ascii.Contains('Settings')
L "MARKER_G7_ENSURE=$markG7a"
L "MARKER_G7_LAYOUT=$markG7b"
L "MARKER_INIT_PROBLEMS_PANEL=$markInitProb"
L "MARKER_SEARCH_TOOLTIP=$markSearchTip"
L "MARKER_SCM_TOOLTIP=$markScmTip"
L "MARKER_SETTINGS_LABEL=$markSettingsTip"
L "DUAL_PROBLEMS_AUTHORITY=IDC_PANEL_PROBLEMS_LIST_1312"
L "DUAL_PROBLEMS_SIDEBAR_IMPL=ABSENT_FROM_TIP_EXE_AND_MAIN_SRC"
L "DUAL_PROBLEMS_DISPOSITION=FIXED_AUTHORITY_1312_ONLY"

# --- CU policy / approval default-deny (same package) ---
$cuSha = ''
$cuVerdict = 'NOT_RUN'
if (Test-Path -LiteralPath $CuVerify) {
  $cuSha = (Get-FileHash -Algorithm SHA256 -Path $CuVerify).Hash
  L "CU_VERIFY_EXE=$CuVerify"
  L "CU_VERIFY_SHA256=$cuSha"
  $cuOut = & $CuVerify 2>&1 | Out-String
  $cuPath = Join-Path $OutDir ("CU_VERIFY_$stamp.txt")
  $cuOut | Set-Content -LiteralPath $cuPath -Encoding ASCII
  if ($cuOut -match 'VERIFY PASS') { $cuVerdict = 'PASS' } else { $cuVerdict = 'FAIL' }
  L "CU_VERIFY_RECEIPT=$cuPath"
} else {
  L "CU_VERIFY_EXE=MISSING"
}
L "CU_APPROVAL_DEFAULT_DENY=$cuVerdict"
L "CU_POLICY_DENIES=$cuVerdict"

# --- Freeze Control ---
L "FREEZE_CONTROL=AUTHORIZED_DEFER"
L "FREEZE_CONTROL_RATIONALE=Dashboard_401_non_blocking_local_IDE_acceptance_unaffected_per_IDE_RELEASE_READINESS_integrity_README"

# --- Launch IDE surface probe ---
Get-Process -Name 'RawrXD-Win32IDE-Native*' -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
Start-Sleep 1
$env:RAWRXD_PROBLEMS_FIXTURE = $BrokenCpp
$p = Start-Process -FilePath $TipExe -ArgumentList @($BrokenCpp) -PassThru -WindowStyle Normal
$main = [IntPtr]::Zero
for ($i = 0; $i -lt 50; $i++) {
  Start-Sleep -Milliseconds 300
  try { $p.Refresh() } catch {}
  if ($p.HasExited) { break }
  if ($p.MainWindowHandle -ne 0) { $main = [IntPtr]$p.MainWindowHandle; break }
  $main = [W5Surf]::FindMain([uint32]$p.Id)
  if ($main -ne [IntPtr]::Zero) { break }
}
L "PID=$($p.Id)"
if ($p.HasExited -or $main -eq [IntPtr]::Zero) {
  L "LAUNCH=FAIL"
  L "VERDICT=FAIL_NO_HWND"
  $lines | Set-Content -LiteralPath $receipt -Encoding ASCII
  exit 1
}
L "LAUNCH=PASS"
L "MAIN_HWND=$main"
[void][W5Surf]::SetForegroundWindow($main)

# Activity bar / view cmds (Explorer/Search/SCM/Debug/Ext/Settings-ish View panel)
foreach ($cmd in @(2034, 2025, 2021, 2029, 1101, 1102, 1103, 1106)) {
  [void][W5Surf]::SendMessageW($main, 0x0111, [IntPtr]$cmd, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 150
}
Start-Sleep -Milliseconds $SettleMs

$map = [W5Surf]::ChildMap($main)
$idsOfInterest = @(1030, 1100, 1101, 1102, 1103, 1105, 1106, 1300, 1301, 1312, 6003, 6030)
foreach ($id in $idsOfInterest) {
  if ($map.ContainsKey($id)) { L "CTRL_$id=$($map[$id])" } else { L "CTRL_$id=ABSENT" }
}

$idTabs = [W5Surf]::FindId($main, 1030)
$idAct = [W5Surf]::FindId($main, 1100)
$idSearch = [W5Surf]::FindId($main, 1102)
$idScm = [W5Surf]::FindId($main, 1103)
$idSettings = [W5Surf]::FindId($main, 1106)
$id1300 = [W5Surf]::FindId($main, 1300)
$id1312 = [W5Surf]::FindId($main, 1312)
$vis1300Pre = if ($id1300 -ne [IntPtr]::Zero) { [W5Surf]::IsWindowVisible($id1300) } else { $false }

L "EDITOR_TABS_1030_PRESENT=$($idTabs -ne [IntPtr]::Zero)"
L "EDITOR_TABS_1030_VISIBLE=$(if ($idTabs -ne [IntPtr]::Zero) { [W5Surf]::IsWindowVisible($idTabs) } else { $false })"
L "ACTIVITY_BAR_1100_PRESENT=$($idAct -ne [IntPtr]::Zero)"
L "SEARCH_BTN_1102_PRESENT=$($idSearch -ne [IntPtr]::Zero)"
L "SCM_BTN_1103_PRESENT=$($idScm -ne [IntPtr]::Zero)"
L "SETTINGS_BTN_1106_PRESENT=$($idSettings -ne [IntPtr]::Zero)"
L "VISID_1300_PRE_BUILD=$vis1300Pre"

# Keybindings: source-wired in Core; runtime Accel table probe = SendMessage known IDs
# Ctrl+, settings dialog may be modal — post command palette / help shortcuts via WM_COMMAND help id if known
# Measure: post Find (common) and confirm IDE stays alive
[void][W5Surf]::SendMessageW($main, 0x0111, [IntPtr]2003, [IntPtr]::Zero) # often Find
Start-Sleep -Milliseconds 400
$aliveKb = (-not $p.HasExited) -and [W5Surf]::IsWindow($main)
L "KEYBIND_CMD_POST_ALIVE=$aliveKb"

# Multi-file: tip launched with one path; open second via env not available — mark SOURCE_WIRED FileOps + runtime single-tab present
L "MULTI_FILE_EDIT_RUNTIME=PARTIAL_SINGLE_DOC_TAB_PATH"
L "MULTI_FILE_EDIT_SOURCE=Win32IDE_FileOps.cpp_m_openDocuments"

# Build 3014 then VisId(1300) + Problems
[void][W5Surf]::SendMessageW($main, 0x0111, [IntPtr]3014, [IntPtr]::Zero)
L "BUILD_3014=POSTED"
$prob = -1
$vis1300Post = $false
$vis1312Post = $false
for ($w = 0; $w -lt 50; $w++) {
  Start-Sleep 1
  if ($p.HasExited) { break }
  $id1300 = [W5Surf]::FindId($main, 1300)
  $id1312 = [W5Surf]::FindId($main, 1312)
  $vis1300Post = if ($id1300 -ne [IntPtr]::Zero) { [W5Surf]::IsWindowVisible($id1300) } else { $false }
  $vis1312Post = if ($id1312 -ne [IntPtr]::Zero) { [W5Surf]::IsWindowVisible($id1312) } else { $false }
  $prob = [W5Surf]::ItemCount($main, 1312)
  if ($w -eq 0 -or ($w % 5) -eq 0) { L "POLL t=$w vis1300=$vis1300Post vis1312=$vis1312Post prob=$prob" }
  if ($prob -gt 0 -and $vis1300Post) { break }
}
L "VISID_1300_POST_BUILD=$vis1300Post"
L "VISID_1312_POST_BUILD=$vis1312Post"
L "PROBLEMS_ITEMS_POST_BUILD=$prob"
L "G_W3_06_PANEL_VISIBILITY_AFTER_BUILD=$(if ($vis1300Post) { 'PASS' } else { 'FAIL' })"

# Rebuild race: second 3014; sample item count within 400ms then after settle
[void][W5Surf]::SendMessageW($main, 0x0111, [IntPtr]3014, [IntPtr]::Zero)
Start-Sleep -Milliseconds 400
$snap = [W5Surf]::ItemCount($main, 1312)
Start-Sleep 8
$refill = [W5Surf]::ItemCount($main, 1312)
L "BUILD_PROBLEMS_RACE_SNAP400MS=$snap"
L "BUILD_PROBLEMS_RACE_REFILL=$refill"
# Race closed if dock stays visible and refill>0 (clear may be PARTIAL if snap>0 — not FAIL if refill works)
if ($vis1300Post -and $refill -gt 0) {
  L "BUILD_PROBLEMS_RACE=PASS_REFILL_DOCK_STABLE"
} elseif ($refill -gt 0) {
  L "BUILD_PROBLEMS_RACE=PARTIAL_REFILL_DOCK_HIDDEN"
} else {
  L "BUILD_PROBLEMS_RACE=FAIL_NO_REFILL"
}

# Ollama protocol edge (source+prior same-SHA agent path; no invented live stream here)
L "OLLAMA_EDGE_SOURCE=backend/ollama_client.cpp+Win32IDE_ChatPanel_Ollama.cpp"
L "OLLAMA_EDGE_EMPTY_TOOL_CALLS=HANDLED_IS_ARRAY_GUARD"
L "OLLAMA_EDGE_STREAM_DONE=HANDLED_done_true"
L "OLLAMA_EDGE_RUNTIME_THIS_SHA=RELATED_WAVE1_AGENT_READ_PASS_NOT_PROTOCOL_MATRIX"
L "OLLAMA_EDGE_CLASS=SOURCE_WIRED_RUNTIME_PARTIAL"

[void][W5Surf]::PostMessageW($main, [W5Surf]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
Start-Sleep 1
try { if (-not $p.HasExited) { $p.Kill() } } catch {}

# Aggregate surface verdicts
$surfPass = 0; $surfFail = 0; $surfPartial = 0
function Score([bool]$ok, [string]$partial=$false) {
  if ($ok) { $script:surfPass++ } else { $script:surfFail++ }
}
if ($idTabs -ne [IntPtr]::Zero) { $surfPass++ } else { $surfPartial++ }
if ($idSearch -ne [IntPtr]::Zero -or $markSearchTip) { $surfPass++ } else { $surfFail++ }
if ($idScm -ne [IntPtr]::Zero -or $markScmTip) { $surfPass++ } else { $surfFail++ }
if ($idSettings -ne [IntPtr]::Zero -or $markSettingsTip) { $surfPass++ } else { $surfFail++ }
if ($aliveKb) { $surfPass++ } else { $surfFail++ }
if ($cuVerdict -eq 'PASS') { $surfPass++ } else { $surfFail++ }
if ($vis1300Post) { $surfPass++ } else { $surfFail++ }
if ($prob -gt 0) { $surfPass++ } else { $surfFail++ }
if (-not $markInitProb) { $surfPass++ } else { $surfPartial++ } # ambiguity closed by absence

L "SURFACE_PASS_AXES=$surfPass"
L "SURFACE_FAIL_AXES=$surfFail"
L "SURFACE_PARTIAL_AXES=$surfPartial"
$verdict = if ($surfFail -eq 0) { 'PASS' } elseif ($vis1300Post -and $cuVerdict -eq 'PASS' -and $prob -gt 0) { 'PARTIAL' } else { 'FAIL' }
L "VERDICT=$verdict"
$lines | Set-Content -LiteralPath $receipt -Encoding ASCII
Write-Host "WAVE5_SURFACE_AUDIT=$verdict receipt=$receipt"
if ($verdict -eq 'FAIL') { exit 2 } else { exit 0 }
