# T15 Autonomous Editing — live tip_ext_host harness (fail-closed)
# PROMOTE=0 CERTIFIED=0 RELEASE=HELD CONTROLLING=D015
# Command: IDM_AI_EDIT=2060 (existing; do NOT invent new ID / do NOT use 3020)
# Path: WM_COMMAND 2060 deterministic repair → disk hash change → 3014 → Problems→0
#       → IDM_EDIT_UNDO=2007 → save → original bytes restored.

param(
    [string]$IdePath = 'F:\rawrxd\build_tip_ext_host_001\bin\RawrXD-Win32IDE-Native-Ext.exe',
    [string]$ResourceHeader = 'F:\rawrxd\src\win32app\Win32IDE_CommandIDs.h',
    [string]$Fixture = 'F:\rawrxd\T080_test_bad.cpp',
    [string]$EvidenceDir = 'F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\FINALIZATION_CHECKLIST_001\T15_AUTONOMOUS_EDITING_001'
)

$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $EvidenceDir | Out-Null
$ReceiptJson = Join-Path $EvidenceDir 'T15.receipt.json'
$WireTxt = Join-Path $EvidenceDir 'T15_WIRE_001.txt'
$Console = Join-Path $EvidenceDir 't15_console_001.txt'
'' | Set-Content -LiteralPath $Console -Encoding ascii

function Require-Define([string]$headerText, [string]$name) {
    $m = [regex]::Match($headerText, "(?m)^\s*#define\s+$([regex]::Escape($name))\s+(\d+)\s*")
    if (-not $m.Success) { return $null }
    return [int]$m.Groups[1].Value
}

function Log([string]$m) {
    $line = "{0} {1}" -f (Get-Date).ToString('o'), $m
    Write-Host $line
    Add-Content -LiteralPath $Console -Value $line -Encoding ascii
}

if (-not (Test-Path -LiteralPath $IdePath)) { throw "IdePath missing: $IdePath" }
if (-not (Test-Path -LiteralPath $ResourceHeader)) { throw "Resource header missing: $ResourceHeader" }
if (-not (Test-Path -LiteralPath $Fixture)) { throw "Fixture missing: $Fixture" }

$header = Get-Content -LiteralPath $ResourceHeader -Raw
$idUndo = Require-Define $header 'IDM_EDIT_UNDO'
$idBuild = Require-Define $header 'IDM_TOOLS_BUILD_PROJECT'
$idAiEdit = Require-Define $header 'IDM_AI_EDIT'
$idSave = Require-Define $header 'IDM_FILE_SAVE'

# Authoritative ID for T15 (interrupt finding): IDM_AI_EDIT=2060
$IdmAiAutonomousEdit = 2060
if ($null -eq $idAiEdit -or $idAiEdit -ne $IdmAiAutonomousEdit) {
    throw "IDM_AI_EDIT expected $IdmAiAutonomousEdit got=$idAiEdit"
}
if ($idUndo -ne 2007) { throw "IDM_EDIT_UNDO expected 2007 got=$idUndo" }
if ($idBuild -ne 3014) { throw "IDM_TOOLS_BUILD_PROJECT expected 3014 got=$idBuild" }

$sha = (Get-FileHash -Algorithm SHA256 -LiteralPath $IdePath).Hash
$asof = (Get-Date).ToUniversalTime().ToString('o')
$TipCwd = Split-Path -Parent $IdePath

# Restore fixture to known-broken bytes before run (idempotent). CRLF once.
$brokenBytes = "int main()`r`n{`r`n    return undeclared_variable_xyz;`r`n}`r`n"
[System.IO.File]::WriteAllText($Fixture, $brokenBytes)
$hashBefore = (Get-FileHash -Algorithm SHA256 -LiteralPath $Fixture).Hash
Log "TIP_SHA256=$sha FIXTURE_BEFORE=$hashBefore IdmAiAutonomousEdit=$IdmAiAutonomousEdit"

Add-Type @"
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class T15CTL {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextLength(IntPtr h);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc f, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr p, EnumProc f, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassName(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint msg, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr PostMessageW(IntPtr h, uint msg, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  public const uint WM_GETTEXTLENGTH = 0x000E;
  public const uint WM_COMMAND = 0x0111;
  public const uint LVM_GETITEMCOUNT = 0x1004;
  public const uint TCM_SETCURSEL = 0x130C;
  public static string Title(IntPtr h) {
    int n = GetWindowTextLength(h); if (n <= 0) return "";
    var sb = new StringBuilder(n+2); GetWindowText(h, sb, n+1); return sb.ToString();
  }
  public static string Cls(IntPtr h) {
    var sb = new StringBuilder(256); GetClassName(h, sb, 256); return sb.ToString();
  }
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h,l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p == pid) {
        string t = Title(h);
        if (!string.IsNullOrEmpty(t) && t.IndexOf("RawrXD", StringComparison.OrdinalIgnoreCase) >= 0) {
          found = h; return false;
        }
      }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static IntPtr FindChildByIdAndClass(IntPtr parent, int id, string className) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(parent, (h, l) => {
      var sb = new StringBuilder(256);
      GetClassName(h, sb, 256);
      if (GetDlgCtrlID(h) == id && string.Equals(sb.ToString(), className, StringComparison.OrdinalIgnoreCase)) {
        found = h; return false;
      }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static int ListViewRows(IntPtr h) {
    if (h == IntPtr.Zero) return -1;
    return (int)SendMessageW(h, LVM_GETITEMCOUNT, IntPtr.Zero, IntPtr.Zero);
  }
}
"@

$env:RAWRXD_PROBLEMS_FIXTURE = $Fixture
$env:RAWRXD_T15_DETERMINISTIC = '1'

$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $IdePath
$psi.Arguments = "`"$Fixture`""
$psi.WorkingDirectory = $TipCwd
$psi.UseShellExecute = $false
$proc = [System.Diagnostics.Process]::Start($psi)
$idePid = $proc.Id
Log "LAUNCHED PID=$idePid"

$mainHwnd = [IntPtr]::Zero
$title = ''
$titleMatch = $false
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 400
    if ($proc.HasExited) { Log "EXITED_EARLY code=$($proc.ExitCode) iter=$i"; break }
    $mainHwnd = [T15CTL]::FindMain([uint32]$idePid)
    if ($mainHwnd -eq [IntPtr]::Zero) { continue }
    $title = [T15CTL]::Title($mainHwnd)
    $titleMatch = ($title -like '*T080_test_bad.cpp*') -or ($title -like '*T080_test_bad*')
    Log "ITER=$i MATCH=$titleMatch TITLE='$title'"
    if ($titleMatch -and $i -ge 4) { break }
}

$problemsBefore = -1
$problemsAfterEdit = -1
$problemsAfterBuild = -1
$hashAfterEdit = $null
$hashAfterUndo = $null
$editPosted = $false
$buildPosted = $false
$undoPosted = $false
$savePosted = $false
$survived = $false
$errors = New-Object System.Collections.Generic.List[string]

if ($mainHwnd -eq [IntPtr]::Zero -or $proc.HasExited) {
    $errors.Add('IDE_NOT_READY')
} else {
    [void][T15CTL]::SetForegroundWindow($mainHwnd)
    $problemsHwnd = [T15CTL]::FindChildByIdAndClass($mainHwnd, 1312, 'SysListView32')
    Log "PROBLEMS_HWND=0x$('{0:X}' -f $problemsHwnd.ToInt64())"

    # Seed Problems rows via build of broken fixture (SendMessage = sync route).
    [void][T15CTL]::SendMessageW($mainHwnd, [T15CTL]::WM_COMMAND, [IntPtr]3014, [IntPtr]::Zero)
    $buildPosted = $true
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        if ($proc.HasExited) { break }
        $problemsHwnd = [T15CTL]::FindChildByIdAndClass($mainHwnd, 1312, 'SysListView32')
        $problemsBefore = [T15CTL]::ListViewRows($problemsHwnd)
        Log "WAIT_PROBLEMS rows=$problemsBefore"
        if ($problemsBefore -gt 0) { break }
        Start-Sleep -Milliseconds 800
    }

    if ($problemsBefore -le 0) {
        $errors.Add("PROBLEMS_BEFORE_EDIT_EXPECTED_GT0 got=$problemsBefore")
    }

    # Deterministic AI edit (2060) — repairs undeclared_variable_xyz → 0 and saves.
    [void][T15CTL]::SendMessageW($mainHwnd, [T15CTL]::WM_COMMAND, [IntPtr]$IdmAiAutonomousEdit, [IntPtr]::Zero)
    $editPosted = $true
    Start-Sleep -Milliseconds 500
    $hashAfterEdit = (Get-FileHash -Algorithm SHA256 -LiteralPath $Fixture).Hash
    Log "HASH_AFTER_EDIT=$hashAfterEdit changed=$($hashAfterEdit -ne $hashBefore)"
    if ($hashAfterEdit -eq $hashBefore) {
        $errors.Add('FIXTURE_HASH_UNCHANGED_AFTER_EDIT')
    }

    # Rebuild — expect Problems rows → 0 after clean compile settles.
    [void][T15CTL]::SendMessageW($mainHwnd, [T15CTL]::WM_COMMAND, [IntPtr]3014, [IntPtr]::Zero)
    Start-Sleep -Milliseconds 1500  # allow clearProblems then cl.exe
    $deadline2 = (Get-Date).AddSeconds(35)
    $stableZero = 0
    $sawZero = $false
    while ((Get-Date) -lt $deadline2) {
        if ($proc.HasExited) { break }
        $problemsHwnd = [T15CTL]::FindChildByIdAndClass($mainHwnd, 1312, 'SysListView32')
        $problemsAfterBuild = [T15CTL]::ListViewRows($problemsHwnd)
        Log "WAIT_PROBLEMS_AFTER_REPAIR rows=$problemsAfterBuild"
        if ($problemsAfterBuild -eq 0) {
            $stableZero++
            if ($stableZero -ge 3) { $sawZero = $true; break }
        } else {
            $stableZero = 0
        }
        Start-Sleep -Milliseconds 800
    }
    if (-not $sawZero) {
        $errors.Add("PROBLEMS_AFTER_REPAIR_EXPECTED_0 got=$problemsAfterBuild")
    }

    # Undo (2007) then Save so disk bytes restore.
    [void][T15CTL]::SendMessageW($mainHwnd, [T15CTL]::WM_COMMAND, [IntPtr]2007, [IntPtr]::Zero)
    $undoPosted = $true
    Start-Sleep -Milliseconds 300
    if ($null -ne $idSave) {
        [void][T15CTL]::SendMessageW($mainHwnd, [T15CTL]::WM_COMMAND, [IntPtr]$idSave, [IntPtr]::Zero)
        $savePosted = $true
        Start-Sleep -Milliseconds 400
    }
    $hashAfterUndo = (Get-FileHash -Algorithm SHA256 -LiteralPath $Fixture).Hash
    Log "HASH_AFTER_UNDO=$hashAfterUndo match_before=$($hashAfterUndo -eq $hashBefore)"
    if ($hashAfterUndo -ne $hashBefore) {
        $errors.Add("UNDO_BYTE_MISMATCH before=$hashBefore after=$hashAfterUndo")
    }
}

$proc.Refresh()
$survived = -not $proc.HasExited
if (-not $proc.HasExited) {
    try { Stop-Process -Id $idePid -Force -ErrorAction Stop; Log "KILLED_PID=$idePid" }
    catch { Log "KILL_ERR $($_.Exception.Message)" }
} else {
    Log "ALREADY_EXITED pid=$idePid"
    $errors.Add('IDE_EXITED_BEFORE_END')
}

# Restore fixture to broken for subsequent gates.
[System.IO.File]::WriteAllText($Fixture, $brokenBytes)

$gateIdsOk = ($idAiEdit -eq 2060 -and $idUndo -eq 2007 -and $idBuild -eq 3014)
$gateHashChanged = ($null -ne $hashAfterEdit -and $hashAfterEdit -ne $hashBefore)
$gateProblemsCleared = ($problemsAfterBuild -eq 0)
$gateUndoMatch = ($null -ne $hashAfterUndo -and $hashAfterUndo -eq $hashBefore)
$gateTitle = [bool]$titleMatch
$gateSurvive = [bool]$survived

$t15 = 'FAIL'
if ($gateIdsOk -and $gateTitle -and $gateHashChanged -and $gateProblemsCleared -and $gateUndoMatch -and $gateSurvive -and $errors.Count -eq 0) {
    $t15 = 'PASS'
}

$asof = (Get-Date).ToUniversalTime().ToString('o')
$receipt = [ordered]@{
    schema = 'RAWRXD_T15_AUTONOMOUS_EDITING_001'
    asof_utc = $asof
    PROMOTE = 0
    CERTIFIED = 0
    RELEASE = 'HELD'
    CONTROLLING = 'D015'
    T15 = $t15
    IdmAiAutonomousEdit = $IdmAiAutonomousEdit
    IDM_AI_EDIT = $idAiEdit
    IDM_EDIT_UNDO = $idUndo
    IDM_TOOLS_BUILD_PROJECT = $idBuild
    IdePath = $IdePath
    IdeSha256 = $sha
    Fixture = $Fixture
    HashBefore = $hashBefore
    HashAfterEdit = $hashAfterEdit
    HashAfterUndo = $hashAfterUndo
    ProblemsBefore = $problemsBefore
    ProblemsAfterBuild = $problemsAfterBuild
    EditPosted = $editPosted
    BuildPosted = $buildPosted
    UndoPosted = $undoPosted
    SavePosted = $savePosted
    TitleMatch = $titleMatch
    Survived = $survived
    FindChildByIdAndClass = 'SysListView32 id=1312'
    RAWRXD_T15_DETERMINISTIC = '1'
    RAWRXD_PROBLEMS_FIXTURE = $Fixture
    errors = @($errors)
    LAW = @('NOT_RUN!=PASS', 'DO_NOT_INVENT_T15_PASS', 'PROMOTE=0', 'NO_T15_EXE_TARGET')
}
$receipt | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $ReceiptJson -Encoding utf8

@"
T15_WIRE_001
ASOF_UTC=$asof
PROMOTE=0
CERTIFIED=0
RELEASE=HELD
CONTROLLING=D015
T15=$t15
LAW=NOT_RUN!=PASS
LAW=DO_NOT_INVENT_T15_PASS
LAW=PROMOTE=0

IdmAiAutonomousEdit=$IdmAiAutonomousEdit
IDM_AI_EDIT=$idAiEdit
IDM_EDIT_UNDO=$idUndo
IDM_TOOLS_BUILD_PROJECT=$idBuild
IdePath=$IdePath
TIP_SHA256=$sha
Fixture=$Fixture
HashBefore=$hashBefore
HashAfterEdit=$hashAfterEdit
HashAfterUndo=$hashAfterUndo
ProblemsBefore=$problemsBefore
ProblemsAfterBuild=$problemsAfterBuild
EditPosted=$editPosted
UndoPosted=$undoPosted
TitleMatch=$titleMatch
Survived=$survived
FindChildByIdAndClass=1312 SysListView32
DETERMINISTIC=RAWRXD_T15_DETERMINISTIC=1
ERRORS=$($errors -join ';')
RECEIPT_JSON=$ReceiptJson
"@ | Set-Content -LiteralPath $WireTxt -Encoding ascii

Log "T15=$t15 PROMOTE=0 RECEIPT=$ReceiptJson"
if ($t15 -ne 'PASS') { exit 2 }
exit 0
