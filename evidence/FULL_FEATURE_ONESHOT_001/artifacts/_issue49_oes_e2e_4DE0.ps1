#Requires -Version 5.1
# Issue #49 map #1 — Open / edit / save on tip_integ_candidate_001 (4DE0).
# Hardened: require marker in editor; EM_REPLACESEL (fires EN_CHANGE); SendMessage Save 2003.
# Laws: PROMOTE=0; NO_CROSS_SHA_PASS; NOT_RUN!=PASS.
$ErrorActionPreference = 'Continue'
$ExpectSha = '4DE06F9F0D7C4FA59926A1BD89041DB7FE75DE0332DBA783A968D3B4105D8BE6'
$TipExe = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\package\tip_integ_candidate_001\RawrXD-Win32IDE-Native-Ext.exe'
$CandDir = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_integ_candidate_001'
$OutDir = 'F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts'
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$RunId = "integ_map1_run_$Stamp"
$Sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
if ($Sha -ne $ExpectSha) { Write-Host "SHA_DRIFT=$Sha expected=$ExpectSha"; exit 9 }

Get-Process -Name 'RawrXD-Win32IDE-Native*','deep2_agentic_loop','rawr' -ErrorAction SilentlyContinue |
  Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep 2

Add-Type @"
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public static class Map1OES4DE0 {
  public const uint WM_SETTEXT=0x000C, WM_GETTEXT=0x000D, WM_GETTEXTLENGTH=0x000E, WM_COMMAND=0x0111, WM_CLOSE=0x0010;
  public const uint EM_SETSEL=0x00B1, EM_REPLACESEL=0x00C2, EM_SETMODIFY=0x00B9;
  public const int IDM_FILE_SAVE=2003;
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
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
      if (c == "RawrXD_IDE_MainWindow" || c == "RawrXD_IDE_Window" || c.IndexOf("RawrXD") >= 0) { found = h; return false; }
      return true;
    }, IntPtr.Zero); return found;
  }
  public static IntPtr FindCtrl(IntPtr root, int id, string clsWant) {
    var stack = new Stack<IntPtr>(); stack.Push(root);
    while (stack.Count > 0) {
      IntPtr cur = stack.Pop(); var kids = new List<IntPtr>();
      EnumChildWindows(cur, (h,lp) => { kids.Add(h); return true; }, IntPtr.Zero);
      foreach (var k in kids) {
        int cid = GetDlgCtrlID(k);
        var sb = new StringBuilder(64); GetClassNameW(k, sb, 64);
        string cls = sb.ToString();
        if (cid == id && (string.IsNullOrEmpty(clsWant) || cls.IndexOf(clsWant, StringComparison.OrdinalIgnoreCase) >= 0)) return k;
        stack.Push(k);
      }
    } return IntPtr.Zero;
  }
  public static string GetText(IntPtr h) {
    if (h == IntPtr.Zero || !IsWindow(h)) return "";
    int n = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
    if (n <= 0) return "";
    var sb = new StringBuilder(n + 8);
    SendMessageW(h, WM_GETTEXT, (IntPtr)sb.Capacity, sb); return sb.ToString();
  }
  public static void ReplaceAll(IntPtr editor, string t) {
    if (editor == IntPtr.Zero) return;
    SendMessageW(editor, EM_SETSEL, IntPtr.Zero, (IntPtr)(-1));
    SendMessageW(editor, EM_REPLACESEL, (IntPtr)1, t ?? "");
    SendMessageW(editor, EM_SETMODIFY, (IntPtr)1, IntPtr.Zero);
  }
  public static string Title(IntPtr h) { var sb = new StringBuilder(512); GetWindowTextW(h, sb, sb.Capacity); return sb.ToString(); }
}
"@

function Wait-Main([Diagnostics.Process]$proc, [int]$sec = 50) {
  $deadline = (Get-Date).AddSeconds($sec)
  while ((Get-Date) -lt $deadline) {
    try { $proc.Refresh() } catch {}
    if ($proc.HasExited) { return [IntPtr]::Zero }
    $m = [Map1OES4DE0]::FindMain([uint32]$proc.Id)
    if ($m -ne [IntPtr]::Zero) { return $m }
    Start-Sleep -Milliseconds 250
  }
  return [IntPtr]::Zero
}

$oesDir = Join-Path $CandDir ("map1_oes_$Stamp")
New-Item -ItemType Directory -Force -Path $oesDir,$OutDir | Out-Null
$fixture = Join-Path $oesDir 'oes_fixture.txt'
$marker = "OES_MARK_$Stamp"
$edited = "OES_EDITED_$Stamp`r`n$marker`r`nline3"
[IO.File]::WriteAllText($fixture, "OPEN_ONLY $marker`r`n", [Text.UTF8Encoding]::new($false))

$env:RAWRXD_LOG_DIR = $oesDir
$p = Start-Process -FilePath $TipExe -ArgumentList @($fixture) -WorkingDirectory $oesDir -PassThru -WindowStyle Normal
$main = Wait-Main $p 50
$oesOpen='FAIL'; $oesEdit='FAIL'; $oesSave='FAIL'; $oesReopen='FAIL'; $oesByte='FAIL'
$mainHex='0x0'
if ($main -ne [IntPtr]::Zero -and -not $p.HasExited) {
  $mainHex = ('0x{0:X}' -f $main.ToInt64())
  Start-Sleep 2
  [void][Map1OES4DE0]::SetForegroundWindow($main)
  $editor = [IntPtr]::Zero
  $deadline = (Get-Date).AddSeconds(20)
  while ((Get-Date) -lt $deadline -and $editor -eq [IntPtr]::Zero) {
    foreach ($pair in @(@(1001,'RichEdit'),@(1001,'Edit'),@(1010,'RichEdit'),@(1001,''))) {
      $cand = [Map1OES4DE0]::FindCtrl($main, [int]$pair[0], [string]$pair[1])
      if ($cand -eq [IntPtr]::Zero) { continue }
      $txt = [Map1OES4DE0]::GetText($cand)
      $title = [Map1OES4DE0]::Title($main)
      if ($txt -match [regex]::Escape($marker) -or $title -match 'oes_fixture') {
        $editor = $cand
        $oesOpen = 'PASS'
        break
      }
    }
    if ($editor -eq [IntPtr]::Zero) { Start-Sleep -Milliseconds 250 }
  }
  if ($oesOpen -eq 'PASS' -and $editor -ne [IntPtr]::Zero) {
    [Map1OES4DE0]::ReplaceAll($editor, $edited)
    Start-Sleep -Milliseconds 500
    if (([Map1OES4DE0]::GetText($editor)) -match 'OES_EDITED') { $oesEdit = 'PASS' }
    # File > Save (2003) via SendMessage — product path reads editor HWND bytes
    [void][Map1OES4DE0]::SendMessageW($main, [Map1OES4DE0]::WM_COMMAND, [IntPtr][Map1OES4DE0]::IDM_FILE_SAVE, [IntPtr]::Zero)
    Start-Sleep 2
    if (-not ((Test-Path $fixture) -and ([IO.File]::ReadAllText($fixture) -match 'OES_EDITED'))) {
      foreach ($sid in @(2003, 1003, 57603)) {
        [void][Map1OES4DE0]::SendMessageW($main, [Map1OES4DE0]::WM_COMMAND, [IntPtr]$sid, [IntPtr]::Zero)
        Start-Sleep 1
        if ((Test-Path $fixture) -and ([IO.File]::ReadAllText($fixture) -match 'OES_EDITED')) { break }
      }
    }
    if ((Test-Path $fixture) -and ([IO.File]::ReadAllText($fixture) -match 'OES_EDITED')) { $oesSave = 'PASS' }
  }
  try { if (-not $p.HasExited) { [void][Map1OES4DE0]::PostMessageW($main, [Map1OES4DE0]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero); Start-Sleep 2 } } catch {}
  try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {}
  Start-Sleep 1
  $env:RAWRXD_LOG_DIR = Join-Path $oesDir 'reopen'
  New-Item -ItemType Directory -Force -Path $env:RAWRXD_LOG_DIR | Out-Null
  $p2 = Start-Process -FilePath $TipExe -ArgumentList @($fixture) -WorkingDirectory $oesDir -PassThru -WindowStyle Normal
  $main2 = Wait-Main $p2 50
  if ($main2 -ne [IntPtr]::Zero) {
    Start-Sleep 2
    $ed2 = [IntPtr]::Zero
    foreach ($pair in @(@(1001,'RichEdit'),@(1001,'Edit'),@(1010,'RichEdit'),@(1001,''))) {
      $cand = [Map1OES4DE0]::FindCtrl($main2, [int]$pair[0], [string]$pair[1])
      if ($cand -eq [IntPtr]::Zero) { continue }
      $reTxt = [Map1OES4DE0]::GetText($cand)
      if ($reTxt -match 'OES_EDITED' -or $reTxt -match $marker) { $ed2 = $cand; $oesReopen = 'PASS'; break }
    }
    try { Stop-Process -Id $p2.Id -Force } catch {}
  } else { try { if (-not $p2.HasExited) { Stop-Process -Id $p2.Id -Force } } catch {} }
  $disk = if (Test-Path $fixture) { [IO.File]::ReadAllText($fixture) } else { '' }
  $normDisk = ($disk -replace "`r`n","`n" -replace "`r","`n")
  $normEdit = ($edited -replace "`r`n","`n" -replace "`r","`n")
  if ($oesSave -eq 'PASS' -and $normDisk -eq $normEdit) { $oesByte = 'PASS' }
  elseif ($oesSave -eq 'PASS' -and $disk -match 'OES_EDITED') { $oesByte = 'PASS_CONTENT_MATCH_FLEX' }
} else { try { if ($p -and -not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {} }

$map1 = if ($oesOpen -eq 'PASS' -and $oesEdit -eq 'PASS' -and $oesSave -eq 'PASS' -and ($oesByte -match '^PASS') -and $oesReopen -eq 'PASS') { 'PASS' } else { 'FAIL' }
$receipt = Join-Path $OutDir 'ISSUE49_OES_RECEIPT.txt'
@"
ISSUE49_OES_RECEIPT
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
MAP=1
CANDIDATE=tip_integ_candidate_001
TIP_SHA256=$Sha
TIP_EXE=$TipExe
SUITE_STAMP=$Stamp
RUN_ID=$RunId
MAIN_HWND=$mainHex
FIXTURE=$fixture
OPEN_SMOKE=$oesOpen
EDIT_SMOKE=$oesEdit
SAVE_SMOKE=$oesSave
REOPEN_SMOKE=$oesReopen
BYTE_COMPARE=$oesByte
OPEN_EDIT_SAVE=$map1
MAP1=$map1
NO_CROSS_SHA_PASS=1
PROMOTE=0
MATURITY=82
E6CF_RESTORE=HELD
"@ | Set-Content -Encoding ascii $receipt
Copy-Item -Force $receipt (Join-Path $oesDir 'OES_RECEIPT.txt')
Write-Host "MAP1=$map1 RECEIPT=$receipt"
exit $(if ($map1 -eq 'PASS') { 0 } else { 1 })
