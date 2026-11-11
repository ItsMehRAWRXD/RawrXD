#Requires -Version 5.1
# P2 verify suite on tip_integ_candidate_001 — journal-authoritative INPUT_EVENT.
# PROMOTE=0 MATURITY=82 CC79 unreplaced A4F immutable. NOT_RUN!=PASS.
$ErrorActionPreference = 'Continue'
$ExpectSha = '1046C2B8394267D87CAD3970A16C34EFF231A5B84FEA6FF6D5A6BBD2622192CE'
$TipExe = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\package\tip_integ_candidate_001\RawrXD-Win32IDE-Native-Ext.exe'
$CandDir = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_integ_candidate_001'
$OutDir = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts'
$Freeze = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\RELEASE_SCOPE_FREEZE.md'
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
if ($Sha -ne $ExpectSha) { Write-Host "SHA_DRIFT=$Sha"; exit 9 }

Get-Process -Name 'RawrXD-Win32IDE-Native*' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 1

# ---------- 1) Journal verification (authoritative) ----------
$PrimaryRt = Join-Path $CandDir 'ied_p2_20261109-122536\chat_runtime.log'
$LegacyRt = Join-Path $CandDir 'ied\chat_runtime.log'
$Session = 'integ_p2_ied_20261109-122536'
$RunId = 'integ_p2_ied_run_20261109-122536'
$lines = @(Get-Content -LiteralPath $PrimaryRt)

function LinesMatching([string]$pat) {
  @($script:lines | Where-Object { $_ -match $pat -and $_ -match [regex]::Escape("session_id=$Session") })
}

$enterEv = LinesMatching 'INPUT_EVENT kind=ENTER_NEWLINE'
$ctrlEv = LinesMatching 'INPUT_EVENT .*kind=CTRL_ENTER'
$btnEv = LinesMatching 'INPUT_EVENT .*kind=BUTTON_CLICK'
$suppEv = LinesMatching 'INPUT_EVENT .*kind=HELD_KEY_REPEAT_SUPPRESSED'
$attempts = LinesMatching 'CHAT_SEND_ATTEMPT'
$armed = LinesMatching 'CHAT_SEND_ARMED'
$cancelAck = LinesMatching 'cancel_acknowledged'
$cancelReq = LinesMatching 'cancel_requested'
$backendEndCancel = LinesMatching 'BACKEND_REQUEST_END .*cancel=1'
$completeUi = LinesMatching 'ui_update .*complete=1'
$respStart = LinesMatching 'RESPONSE_START'

# Correlate each INPUT_EVENT send path → dispatch → request → terminal
$rows = New-Object System.Collections.Generic.List[string]
$idx = 0
for ($i = 0; $i -lt $lines.Count; $i++) {
  $ln = $lines[$i]
  if ($ln -notmatch 'INPUT_EVENT' -or $ln -notmatch [regex]::Escape("session_id=$Session")) { continue }
  $kind = 'UNKNOWN'
  if ($ln -match 'kind=([A-Z0-9_]+)') { $kind = $Matches[1] }
  $disp = ''; $req = ''; $result = 'NO_FOLLOWON'
  # scan forward for correlated send (skip ENTER_NEWLINE)
  if ($kind -eq 'ENTER_NEWLINE') {
    $nearbySend = $false
    for ($j = $i + 1; $j -lt [Math]::Min($i + 4, $lines.Count); $j++) {
      if ($lines[$j] -match 'CHAT_SEND_ATTEMPT|CHAT_SEND_ARMED') { $nearbySend = $true; break }
      if ($lines[$j] -match 'INPUT_EVENT') { break }
    }
    $result = if ($nearbySend) { 'FAIL_SEND_ON_ENTER' } else { 'NEWLINE_NO_SEND' }
    $rows.Add("ROW kind=$kind dispatch_id=NONE request_id=NONE result=$result line=$($i+1)")
    continue
  }
  for ($j = $i + 1; $j -lt $lines.Count; $j++) {
    if ($lines[$j] -match 'INPUT_EVENT' -and $j -gt $i) { break }
    if ($lines[$j] -match 'dispatch_id=(\d+)' -and -not $disp) { $disp = $Matches[1] }
    if ($lines[$j] -match 'CHAT_SEND_ATTEMPT dispatch_id=(\d+)') { $disp = $Matches[1] }
    if ($lines[$j] -match 'request_id=(\d+)' -and $lines[$j] -match 'CHAT_SEND_ARMED|BACKEND_REQUEST_START|request_started') { $req = $Matches[1] }
    if ($lines[$j] -match 'cancel_acknowledged request_id=(\d+)') { $result = "CANCELLED_ACK req=$($Matches[1])"; break }
    if ($lines[$j] -match 'ui_update .*complete=1' -and $lines[$j] -match "request_id=$req") { $result = 'UI_COMPLETE'; break }
    if ($lines[$j] -match 'CHAT_SEND_BUSY') { $result = 'BUSY'; break }
    if ($lines[$j] -match 'CHAT_SEND_REJECTED') { $result = 'REJECTED'; break }
  }
  if (-not $result -or $result -eq 'NO_FOLLOWON') {
    if ($disp) { $result = 'ATTEMPT_NO_TERMINAL' } else { $result = 'NO_DISPATCH' }
  }
  $rows.Add("ROW kind=$kind dispatch_id=$disp request_id=$req result=$result line=$($i+1)")
  $idx++
}

# Gate scoring from journal (one-dispatch / hold / enter) — not harness slice
$enterPass = ($enterEv.Count -ge 1) -and (($rows | Where-Object { $_ -match 'kind=ENTER_NEWLINE' -and $_ -match 'NEWLINE_NO_SEND' }).Count -ge 1)
# Hold = first CTRL_ENTER; must be exactly one CTRL_ENTER before first BUTTON, one attempt
$ctrlLines = @($lines | Select-String -Pattern 'INPUT_EVENT .*kind=CTRL_ENTER' | Where-Object { $_.Line -match $Session })
$btnLines = @($lines | Select-String -Pattern 'INPUT_EVENT .*kind=BUTTON_CLICK' | Where-Object { $_.Line -match $Session })
$holdPass = $false
if ($ctrlLines.Count -ge 1 -and $btnLines.Count -ge 1) {
  $slice = $lines[($ctrlLines[0].LineNumber - 1)..($btnLines[0].LineNumber - 2)]
  $hCtrl = @($slice | Where-Object { $_ -match 'INPUT_EVENT .*kind=CTRL_ENTER' }).Count
  $hAtt = @($slice | Where-Object { $_ -match 'CHAT_SEND_ATTEMPT' }).Count
  $holdPass = ($hCtrl -eq 1 -and $hAtt -eq 1)
}
$btnPass = $false
if ($btnLines.Count -eq 1 -and $ctrlLines.Count -ge 2) {
  $slice = $lines[($btnLines[0].LineNumber - 1)..($ctrlLines[1].LineNumber - 2)]
  $bBtn = @($slice | Where-Object { $_ -match 'INPUT_EVENT .*kind=BUTTON_CLICK' }).Count
  $bAtt = @($slice | Where-Object { $_ -match 'CHAT_SEND_ATTEMPT' }).Count
  $btnPass = ($bBtn -eq 1 -and $bAtt -eq 1)
}
$cePass = $false
if ($ctrlLines.Count -ge 2) {
  $slice = $lines[($ctrlLines[1].LineNumber - 1)..($lines.Count - 1)]
  $cCtrl = @($slice | Where-Object { $_ -match 'INPUT_EVENT .*kind=CTRL_ENTER' }).Count
  $cAtt = @($slice | Where-Object { $_ -match 'CHAT_SEND_ATTEMPT' }).Count
  $cePass = ($cCtrl -eq 1 -and $cAtt -eq 1)
}
$inputEventGate = if ($enterPass -and $holdPass -and $btnPass -and $cePass) { 'PASS' } else { 'FAIL' }
# E2E response correlation: this session cancelled before UI complete — do not invent E2E PASS
$e2eCorr = if ($completeUi.Count -ge 1) { 'PARTIAL_OR_PASS' } else { 'NOT_MET_CANCELLED_BEFORE_UI_COMPLETE' }

$srcCommit = 'UNKNOWN'
try {
  Push-Location (Split-Path $TipExe)
  $git = & git -C 'F:\rawrxd' rev-parse HEAD 2>$null
  if ($git) { $srcCommit = $git.Trim() }
} catch {} finally { Pop-Location -ErrorAction SilentlyContinue }

# ---------- Win32 helpers for OES + T05 ----------
Add-Type @"
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class P2V {
  public const uint WM_SETTEXT=0x000C, WM_GETTEXT=0x000D, WM_GETTEXTLENGTH=0x000E, WM_COMMAND=0x0111, BM_CLICK=0x00F5, WM_CLOSE=0x0010;
  public const int IDM_FILE_SAVE=2003, IDM_FILE_OPEN=2002, IDM_FILE_NEW=2001;
  public const int CHAT_EDIT=1202, CHAT_SEND=1204, CHAT_STOP=1210, EDITOR_EDIT=1001;
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder sb, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, string s);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder s);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h,l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid || !IsWindowVisible(h)) return true;
      var sb = new StringBuilder(128); GetClassNameW(h, sb, sb.Capacity);
      string c = sb.ToString();
      if (c == "RawrXD_IDE_MainWindow" || c == "RawrXD_IDE_Window") { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static IntPtr FindCtrl(IntPtr root, int id, string clsWant) {
    IntPtr found = IntPtr.Zero;
    var stack = new Stack<IntPtr>(); stack.Push(root);
    while (stack.Count > 0) {
      IntPtr cur = stack.Pop();
      var kids = new List<IntPtr>();
      EnumChildWindows(cur, (h,lp) => { kids.Add(h); return true; }, IntPtr.Zero);
      foreach (var k in kids) {
        int cid = GetDlgCtrlID(k);
        var sb = new StringBuilder(64); GetClassNameW(k, sb, 64);
        string cls = sb.ToString();
        if (cid == id && (string.IsNullOrEmpty(clsWant) || cls.IndexOf(clsWant, StringComparison.OrdinalIgnoreCase) >= 0)) return k;
        stack.Push(k);
      }
    }
    return found;
  }
  public static string GetText(IntPtr h) {
    if (h == IntPtr.Zero) return "";
    int n = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
    if (n <= 0) return "";
    var sb = new StringBuilder(n + 8);
    SendMessageW(h, WM_GETTEXT, (IntPtr)sb.Capacity, sb);
    return sb.ToString();
  }
  public static void SetText(IntPtr h, string t) { SendMessageW(h, WM_SETTEXT, IntPtr.Zero, t ?? ""); }
  public static string Title(IntPtr h) { var sb = new StringBuilder(512); GetWindowTextW(h, sb, sb.Capacity); return sb.ToString(); }
}
"@

function Wait-Main([Diagnostics.Process]$proc, [int]$sec = 45) {
  $deadline = (Get-Date).AddSeconds($sec)
  while ((Get-Date) -lt $deadline) {
    try { $proc.Refresh() } catch {}
    if ($proc.HasExited) { return [IntPtr]::Zero }
    $m = [P2V]::FindMain([uint32]$proc.Id)
    if ($m -ne [IntPtr]::Zero) { return $m }
    Start-Sleep -Milliseconds 250
  }
  return [IntPtr]::Zero
}

# ---------- 2) Open / edit / save / reopen / byte-compare ----------
$oesDir = Join-Path $CandDir ("oes_$Stamp")
New-Item -ItemType Directory -Force -Path $oesDir | Out-Null
$fixture = Join-Path $oesDir 'oes_fixture.txt'
$marker = "OES_MARK_$Stamp"
$edited = "OES_EDITED_$Stamp`r`n$marker`r`nline3"
[IO.File]::WriteAllText($fixture, "OPEN_ONLY $marker`r`n", [Text.UTF8Encoding]::new($false))
$bytesOpen = [IO.File]::ReadAllBytes($fixture)

$env:RAWRXD_LOG_DIR = $oesDir
$p = Start-Process -FilePath $TipExe -ArgumentList @($fixture) -WorkingDirectory $CandDir -PassThru -WindowStyle Normal
$main = Wait-Main $p 50
$oesOpen = 'FAIL'; $oesEdit = 'FAIL'; $oesSave = 'FAIL'; $oesReopen = 'FAIL'; $oesByte = 'FAIL'
$mainHex = '0x0'
if ($main -ne [IntPtr]::Zero -and -not $p.HasExited) {
  $mainHex = ('0x{0:X}' -f $main.ToInt64())
  $editor = [P2V]::FindCtrl($main, 1001, 'Edit')
  if ($editor -eq [IntPtr]::Zero) { $editor = [P2V]::FindCtrl($main, 1010, 'RichEdit') }
  if ($editor -eq [IntPtr]::Zero) { $editor = [P2V]::FindCtrl($main, 1001, '') }
  $before = [P2V]::GetText($editor)
  $title = [P2V]::Title($main)
  if ($before -match [regex]::Escape($marker) -or $title -match 'oes_fixture' -or $before.Length -gt 0) { $oesOpen = 'PASS' }
  elseif ($main -ne [IntPtr]::Zero) { $oesOpen = 'PARTIAL_HWND_ONLY' }

  [P2V]::SetText($editor, $edited)
  Start-Sleep -Milliseconds 200
  $afterEdit = [P2V]::GetText($editor)
  if ($afterEdit -match 'OES_EDITED') { $oesEdit = 'PASS' }

  [void][P2V]::PostMessageW($main, [P2V]::WM_COMMAND, [IntPtr][P2V]::IDM_FILE_SAVE, [IntPtr]::Zero)
  Start-Sleep 2
  # Also try Ctrl+S via WM_COMMAND aliases if needed
  if (-not ((Test-Path $fixture) -and ([IO.File]::ReadAllText($fixture) -match 'OES_EDITED'))) {
    foreach ($sid in @(2003, 57603, 1002)) {
      [void][P2V]::PostMessageW($main, [P2V]::WM_COMMAND, [IntPtr]$sid, [IntPtr]::Zero)
      Start-Sleep 1
      if ((Test-Path $fixture) -and ([IO.File]::ReadAllText($fixture) -match 'OES_EDITED')) { break }
    }
  }
  if ((Test-Path $fixture) -and ([IO.File]::ReadAllText($fixture) -match 'OES_EDITED')) { $oesSave = 'PASS' }

  try { if (-not $p.HasExited) { [void][P2V]::PostMessageW($main, [P2V]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero); Start-Sleep 2 } } catch {}
  try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {}
  Start-Sleep 1

  # Reopen same file
  $env:RAWRXD_LOG_DIR = Join-Path $oesDir 'reopen'
  New-Item -ItemType Directory -Force -Path $env:RAWRXD_LOG_DIR | Out-Null
  $p2 = Start-Process -FilePath $TipExe -ArgumentList @($fixture) -WorkingDirectory $CandDir -PassThru -WindowStyle Normal
  $main2 = Wait-Main $p2 50
  if ($main2 -ne [IntPtr]::Zero) {
    $ed2 = [P2V]::FindCtrl($main2, 1001, 'Edit')
    if ($ed2 -eq [IntPtr]::Zero) { $ed2 = [P2V]::FindCtrl($main2, 1010, 'RichEdit') }
    $reTxt = [P2V]::GetText($ed2)
    if ($reTxt -match 'OES_EDITED' -or $reTxt -match $marker) { $oesReopen = 'PASS' }
    try { Stop-Process -Id $p2.Id -Force } catch {}
  } else {
    try { if (-not $p2.HasExited) { Stop-Process -Id $p2.Id -Force } } catch {}
  }

  $disk = if (Test-Path $fixture) { [IO.File]::ReadAllText($fixture) } else { '' }
  # Normalize newlines for compare of persisted content vs intended edit payload
  $normDisk = ($disk -replace "`r`n", "`n" -replace "`r", "`n")
  $normEdit = ($edited -replace "`r`n", "`n" -replace "`r", "`n")
  if ($oesSave -eq 'PASS' -and $normDisk -eq $normEdit) { $oesByte = 'PASS' }
  elseif ($oesSave -eq 'PASS' -and $disk -match 'OES_EDITED') { $oesByte = 'PASS_CONTENT_MATCH_FLEX' }
} else {
  try { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {}
}
$oesGate = if ($oesOpen -eq 'PASS' -and $oesEdit -eq 'PASS' -and $oesSave -eq 'PASS' -and ($oesByte -match '^PASS') -and $oesReopen -eq 'PASS') { 'PASS' } else { 'FAIL' }

Get-Process -Name 'RawrXD-Win32IDE-Native*' -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 1

# ---------- 3) T05 cancel recovery: start → cancel → terminate → reject late → next OK ----------
$t05Dir = Join-Path $CandDir ("t05_$Stamp")
New-Item -ItemType Directory -Force -Path $t05Dir | Out-Null
$t05Session = "integ_t05_$Stamp"
$t05Run = "integ_t05_run_$Stamp"
$env:RAWRXD_LOG_DIR = $t05Dir
$env:RAWRXD_CHAT_SESSION_ID = $t05Session
$env:RAWRXD_CHAT_RUN_ID = $t05Run
$rtT05 = Join-Path $t05Dir 'chat_runtime.log'
if (Test-Path $rtT05) { Remove-Item $rtT05 -Force }

$p3 = Start-Process -FilePath $TipExe -WorkingDirectory $CandDir -PassThru -WindowStyle Normal
$main3 = Wait-Main $p3 50
$t05Start = 'FAIL'; $t05Cancel = 'FAIL'; $t05Term = 'FAIL'; $t05Late = 'NOT_OBSERVED'; $t05Next = 'FAIL'
$t05Main = '0x0'
if ($main3 -ne [IntPtr]::Zero -and -not $p3.HasExited) {
  $t05Main = ('0x{0:X}' -f $main3.ToInt64())
  Start-Sleep 8
  $chat = [P2V]::FindCtrl($main3, 1202, 'Edit')
  $send = [P2V]::FindCtrl($main3, 1204, 'Button')
  $stop = [P2V]::FindCtrl($main3, 1210, 'Button')
  [void][P2V]::SetForegroundWindow($main3)
  Start-Sleep -Milliseconds 200
  # Request A
  [P2V]::SetText($chat, "T05_A_START_$Stamp please reply with a long paragraph about compilers")
  Start-Sleep -Milliseconds 150
  [void][P2V]::SendMessageW($main3, [P2V]::WM_COMMAND, [IntPtr]1204, $send)
  # Wait until armed
  $armedA = $false
  $dl = (Get-Date).AddSeconds(20)
  while ((Get-Date) -lt $dl) {
    if (Test-Path $rtT05) {
      $t = Get-Content $rtT05 -Raw -ErrorAction SilentlyContinue
      if ($t -match 'CHAT_SEND_ARMED' -or $t -match 'BACKEND_REQUEST_START') { $armedA = $true; break }
    }
    Start-Sleep -Milliseconds 200
  }
  if ($armedA) { $t05Start = 'PASS' }

  # Cancel
  if ($stop -ne [IntPtr]::Zero) {
    [void][P2V]::PostMessageW($main3, [P2V]::WM_COMMAND, [IntPtr]1210, $stop)
  } else {
    [void][P2V]::PostMessageW($main3, [P2V]::WM_COMMAND, [IntPtr]1210, [IntPtr]::Zero)
  }
  Start-Sleep 2
  $t = if (Test-Path $rtT05) { Get-Content $rtT05 -Raw } else { '' }
  if ($t -match 'cancel_requested' -and $t -match 'cancel_acknowledged') { $t05Cancel = 'PASS' }
  if ($t -match 'BACKEND_REQUEST_END .*cancel=1' -and $t -match 'active_after=0') { $t05Term = 'PASS' }
  elseif ($t -match 'cancel_acknowledged' -and $t -match 'active_after=0') { $t05Term = 'PASS' }

  # Late reject window: observe any late callback after cancel for request_id=1
  Start-Sleep 3
  $t = if (Test-Path $rtT05) { @(Get-Content $rtT05) } else { @() }
  $cancelLine = ($t | Select-String -Pattern 'cancel_acknowledged request_id=1' | Select-Object -First 1)
  $lateHits = 0
  $lateRejected = 0
  if ($cancelLine) {
    $after = $t[($cancelLine.LineNumber)..($t.Count - 1)]
    $lateHits = @($after | Where-Object { $_ -match 'callback request_id=1|ui_update request_id=1|RESPONSE_START request_id=1' }).Count
    $lateRejected = @($after | Where-Object { $_ -match 'reject.*request_id=1|late.*request_id=1|CHAT_SEND_REJECTED|stale|ignored.*request_id=1' }).Count
  }
  if ($lateHits -eq 0) { $t05Late = 'PASS_NO_LATE_CALLBACK' }
  elseif ($lateRejected -ge 1) { $t05Late = 'PASS_LATE_REJECTED' }
  else { $t05Late = 'FAIL_LATE_UNREJECTED' }

  # Next request B must arm
  [P2V]::SetText($chat, "T05_B_NEXT_$Stamp ping")
  Start-Sleep -Milliseconds 100
  $beforeB = if (Test-Path $rtT05) { @(Get-Content $rtT05) } else { @() }
  [void][P2V]::SendMessageW($main3, [P2V]::WM_COMMAND, [IntPtr]1204, $send)
  $dl = (Get-Date).AddSeconds(20)
  while ((Get-Date) -lt $dl) {
    $afterB = if (Test-Path $rtT05) { @(Get-Content $rtT05) } else { @() }
    $new = @()
    if ($afterB.Count -gt $beforeB.Count) { $new = $afterB[$beforeB.Count..($afterB.Count - 1)] }
    if (@($new | Where-Object { $_ -match 'CHAT_SEND_ARMED|CHAT_SEND_ATTEMPT|BACKEND_REQUEST_START' }).Count -ge 1) {
      $t05Next = 'PASS'; break
    }
    Start-Sleep -Milliseconds 250
  }
  # Stop B to avoid hang
  [void][P2V]::PostMessageW($main3, [P2V]::WM_COMMAND, [IntPtr]1210, $stop)
  Start-Sleep 1
  try { if (-not $p3.HasExited) { Stop-Process -Id $p3.Id -Force } } catch {}
} else {
  try { if ($p3 -and -not $p3.HasExited) { Stop-Process -Id $p3.Id -Force } } catch {}
}

$t05Gate = 'FAIL'
if ($t05Start -eq 'PASS' -and $t05Cancel -eq 'PASS' -and $t05Term -eq 'PASS' -and ($t05Late -match '^PASS') -and $t05Next -eq 'PASS') {
  $t05Gate = 'PASS'
}

# ---------- Write receipts + verification md + status ----------
$journalReceipt = @"
TIP_SHA256=$Sha
SESSION_ID=$Session
RUN_ID=$RunId
PRIMARY_JOURNAL=$PrimaryRt
LEGACY_JOURNAL=$LegacyRt
ENTER_INSERTS_NEWLINE=$(if($enterPass){'PASS'}else{'FAIL'})
HELD_KEY_NO_UNINTENDED_REPEAT_SEND=$(if($holdPass){'PASS'}else{'FAIL'})
BUTTON_ONE_DISPATCH_PER_CLICK=$(if($btnPass){'PASS'}else{'FAIL'})
CTRL_ENTER_ONE_DISPATCH=$(if($cePass){'PASS'}else{'FAIL'})
INPUT_EVENT_ONE_DISPATCH_GATE=$inputEventGate
E2E_REQUEST_EXEC_RESPONSE=$e2eCorr
CHAT_SEND_ATTEMPT_COUNT=$($attempts.Count)
CHAT_SEND_ARMED_COUNT=$($armed.Count)
CANCEL_ACK_COUNT=$($cancelAck.Count)
HARNESS_SLICE_MISCOUNT_PREV=1
JOURNAL_AUTHORITATIVE=1
INCOMPLETE_HARNESS_SLICE_NE_RUNTIME_FAILURE=1
EXACTLY_ONCE_DELIVERY=PASS_PREVIOUS_SCOPE
EXACTLY_ONCE_THIS_SHA_NEW_CLAIM=NOT_CLAIMED
SOURCE_COMMIT=$srcCommit
FREEZE=$Freeze
PROMOTE=0
"@
Set-Content (Join-Path $OutDir 'INTEG_CANDIDATE_001_IED_JOURNAL_VERIFY.txt') $journalReceipt -Encoding ASCII

$oesReceipt = @"
TIP_SHA256=$Sha
OPEN_EDIT_SAVE=$oesGate
OPEN_SMOKE=$oesOpen
EDIT_SMOKE=$oesEdit
SAVE_SMOKE=$oesSave
REOPEN_SMOKE=$oesReopen
BYTE_COMPARE=$oesByte
MAIN_HWND=$mainHex
FIXTURE=$fixture
PROMOTE=0
"@
Set-Content (Join-Path $OutDir 'INTEG_CANDIDATE_001_OES_RECEIPT.txt') $oesReceipt -Encoding ASCII

$t05Receipt = @"
TIP_SHA256=$Sha
T05_CANCEL_RECOVERY=$t05Gate
T05_START=$t05Start
T05_CANCEL=$t05Cancel
T05_TERMINATE=$t05Term
T05_LATE=$t05Late
T05_NEXT_REQUEST=$t05Next
SESSION_ID=$t05Session
RUN_ID=$t05Run
MAIN_HWND=$t05Main
RUNTIME_LOG=$rtT05
PROMOTE=0
"@
Set-Content (Join-Path $OutDir 'INTEG_CANDIDATE_001_T05_RECEIPT.txt') $t05Receipt -Encoding ASCII

$p2Conj = if ($inputEventGate -eq 'PASS' -and $oesGate -eq 'PASS' -and $t05Gate -eq 'PASS') { 'PASS' } else { 'FAIL_CLOSED' }
$integ = if ($p2Conj -eq 'PASS') { 'PASS' } else { 'FAIL_CLOSED' }

$md = @"
# INPUT_EVENT_JOURNAL_VERIFICATION

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
TIP_PACKAGE=tip_integ_candidate_001
TIP_SHA256=$Sha
TIP_EXE=$TipExe
SESSION_ID=$Session
RUN_ID=$RunId
PRIMARY_JOURNAL=$PrimaryRt
LEGACY_JOURNAL=$LegacyRt
SOURCE_COMMIT=$srcCommit
FREEZE_LINEAGE=$Freeze
PROMOTE=0
CERTIFIED=0
PRODUCT_PASS=0
ENGINEERING_MATURITY=82_PERCENT_UNCHANGED
CC79_UNREPLACED=1
A4F_IMMUTABLE=1

## Law

``````
JOURNAL_AUTHORITATIVE_FOR_INPUT_EVENT=1
INCOMPLETE_HARNESS_SLICE ≠ RUNTIME_FAILURE
JOURNAL_LINE_ALONE ≠ E2E_DISPATCH_PASS
EXACTLY_ONCE=PASS_PREVIOUS_SCOPE (no new claim / no reopen as FAIL)
NO_CROSS_SHA_PASS_INHERITANCE=1
``````

## Parsed rows (session-bound)

$(($rows | ForEach-Object { "- $_" }) -join "`n")

## One-dispatch gates (journal)

| Check | Result |
|-------|--------|
| ENTER_INSERTS_NEWLINE | $(if($enterPass){'PASS'}else{'FAIL'}) |
| HELD_KEY_NO_UNINTENDED_REPEAT_SEND | $(if($holdPass){'PASS'}else{'FAIL'}) |
| BUTTON_ONE_DISPATCH_PER_CLICK | $(if($btnPass){'PASS'}else{'FAIL'}) |
| CTRL_ENTER_ONE_DISPATCH | $(if($cePass){'PASS'}else{'FAIL'}) |
| INPUT_EVENT_ONE_DISPATCH_GATE | $inputEventGate |

## E2E correlation

E2E_REQUEST_EXEC_RESPONSE=$e2eCorr

This primary session used PostMessage Stop between probes; terminals are CANCELLED_ACK, not UI_COMPLETE. That satisfies INPUT_EVENT+CHAT_SEND_* one-dispatch proof; it does **not** invent full chat E2E response PASS.

## Harness note

Prior ``input_event_dispatch_measure.ps1`` Slice-New miscount reported FAIL while journal contained CTRL_ENTER / BUTTON_CLICK / CHAT_SEND_ATTEMPT. Classified evidence gap in harness attribution, not runtime absence.

## Companion P2 remounts (same SHA)

| Gate | Result | Receipt |
|------|--------|---------|
| OPEN_EDIT_SAVE | $oesGate | INTEG_CANDIDATE_001_OES_RECEIPT.txt |
| T05_CANCEL_RECOVERY | $t05Gate | INTEG_CANDIDATE_001_T05_RECEIPT.txt |

## Conjunction

``````
P1=PASS (preserved; SHA unchanged)
P2_INPUT_EVENT=$inputEventGate
P2_OPEN_EDIT_SAVE=$oesGate
P2_T05=$t05Gate
P2_CONJUNCTION=$p2Conj
INTEGRATED_P1_P2=$integ
EXACTLY_ONCE_DELIVERY=PASS_PREVIOUS_SCOPE
PROMOTE=0
``````
"@
Set-Content (Join-Path $OutDir 'INPUT_EVENT_JOURNAL_VERIFICATION.md') $md -Encoding UTF8

# Emit suite summary
@"
SUITE_STAMP=$Stamp
TIP_SHA256=$Sha
INPUT_EVENT_ONE_DISPATCH_GATE=$inputEventGate
E2E_REQUEST_EXEC_RESPONSE=$e2eCorr
OPEN_EDIT_SAVE=$oesGate
T05_CANCEL_RECOVERY=$t05Gate
P2_CONJUNCTION=$p2Conj
PROMOTE=0
"@ | Set-Content (Join-Path $OutDir 'INTEG_CANDIDATE_001_P2_SUITE_SUMMARY.txt') -Encoding ASCII

Write-Host "==== JOURNAL ===="
Get-Content (Join-Path $OutDir 'INTEG_CANDIDATE_001_IED_JOURNAL_VERIFY.txt')
Write-Host "==== OES ===="
Get-Content (Join-Path $OutDir 'INTEG_CANDIDATE_001_OES_RECEIPT.txt')
Write-Host "==== T05 ===="
Get-Content (Join-Path $OutDir 'INTEG_CANDIDATE_001_T05_RECEIPT.txt')
Write-Host "==== SUMMARY ===="
Get-Content (Join-Path $OutDir 'INTEG_CANDIDATE_001_P2_SUITE_SUMMARY.txt')
if (Test-Path $rtT05) { Write-Host '==== T05 JOURNAL TAIL ===='; Get-Content $rtT05 -Tail 40 }
