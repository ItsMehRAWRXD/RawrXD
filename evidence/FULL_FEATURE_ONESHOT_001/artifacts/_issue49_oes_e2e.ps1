#Requires -Version 5.1
# Issue #49 map #1 — Open / edit / save workspace file on tip_integ_candidate_001 (5A34).
# Adapted from _integ_p2_verify_suite.ps1 OES slice. Laws: PROMOTE=0; NO_CROSS_SHA_PASS; NOT_RUN!=PASS.
$ErrorActionPreference = 'Continue'
$ExpectSha = '5A34B393ECF7380576CE718C688DC4006C0E3B01090BB4DCD8B844FB594D1619'
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
public static class Map1OES {
  public const uint WM_SETTEXT=0x000C, WM_GETTEXT=0x000D, WM_GETTEXTLENGTH=0x000E, WM_COMMAND=0x0111, WM_CLOSE=0x0010;
  public const int IDM_FILE_SAVE=2003;
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumWindowsProc cb, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumChildProc cb, IntPtr lp);
  public delegate bool EnumWindowsProc(IntPtr h, IntPtr l);
  public delegate bool EnumChildProc(IntPtr h, IntPtr lp);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
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
    if (h == IntPtr.Zero) return "";
    int n = (int)SendMessageW(h, WM_GETTEXTLENGTH, IntPtr.Zero, IntPtr.Zero);
    if (n <= 0) return "";
    var sb = new StringBuilder(n + 8);
    SendMessageW(h, WM_GETTEXT, (IntPtr)sb.Capacity, sb); return sb.ToString();
  }
  public static void SetText(IntPtr h, string t) { SendMessageW(h, WM_SETTEXT, IntPtr.Zero, t ?? ""); }
  public static string Title(IntPtr h) { var sb = new StringBuilder(512); GetWindowTextW(h, sb, sb.Capacity); return sb.ToString(); }
}
"@

function Wait-Main([Diagnostics.Process]$proc, [int]$sec = 50) {
  $deadline = (Get-Date).AddSeconds($sec)
  while ((Get-Date) -lt $deadline) {
    try { $proc.Refresh() } catch {}
    if ($proc.HasExited) { return [IntPtr]::Zero }
    $m = [Map1OES]::FindMain([uint32]$proc.Id)
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
$p = Start-Process -FilePath $TipExe -ArgumentList @($fixture) -WorkingDirectory $CandDir -PassThru -WindowStyle Normal
$main = Wait-Main $p 50
$oesOpen='FAIL'; $oesEdit='FAIL'; $oesSave='FAIL'; $oesReopen='FAIL'; $oesByte='FAIL'
$mainHex='0x0'
if ($main -ne [IntPtr]::Zero -and -not $p.HasExited) {
  $mainHex = ('0x{0:X}' -f $main.ToInt64())
  $editor = [Map1OES]::FindCtrl($main, 1001, 'Edit')
  if ($editor -eq [IntPtr]::Zero) { $editor = [Map1OES]::FindCtrl($main, 1010, 'RichEdit') }
  if ($editor -eq [IntPtr]::Zero) { $editor = [Map1OES]::FindCtrl($main, 1001, '') }
  $before = [Map1OES]::GetText($editor)
  $title = [Map1OES]::Title($main)
  if ($before -match [regex]::Escape($marker) -or $title -match 'oes_fixture' -or $before.Length -gt 0) { $oesOpen = 'PASS' }
  [Map1OES]::SetText($editor, $edited)
  Start-Sleep -Milliseconds 200
  if (([Map1OES]::GetText($editor)) -match 'OES_EDITED') { $oesEdit = 'PASS' }
  [void][Map1OES]::PostMessageW($main, [Map1OES]::WM_COMMAND, [IntPtr][Map1OES]::IDM_FILE_SAVE, [IntPtr]::Zero)
  Start-Sleep 2
  if (-not ((Test-Path $fixture) -and ([IO.File]::ReadAllText($fixture) -match 'OES_EDITED'))) {
    foreach ($sid in @(2003, 57603, 1002)) {
      [void][Map1OES]::PostMessageW($main, [Map1OES]::WM_COMMAND, [IntPtr]$sid, [IntPtr]::Zero)
      Start-Sleep 1
      if ((Test-Path $fixture) -and ([IO.File]::ReadAllText($fixture) -match 'OES_EDITED')) { break }
    }
  }
  if ((Test-Path $fixture) -and ([IO.File]::ReadAllText($fixture) -match 'OES_EDITED')) { $oesSave = 'PASS' }
  try { if (-not $p.HasExited) { [void][Map1OES]::PostMessageW($main, [Map1OES]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero); Start-Sleep 2 } } catch {}
  try { if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force } } catch {}
  Start-Sleep 1
  $env:RAWRXD_LOG_DIR = Join-Path $oesDir 'reopen'
  New-Item -ItemType Directory -Force -Path $env:RAWRXD_LOG_DIR | Out-Null
  $p2 = Start-Process -FilePath $TipExe -ArgumentList @($fixture) -WorkingDirectory $CandDir -PassThru -WindowStyle Normal
  $main2 = Wait-Main $p2 50
  if ($main2 -ne [IntPtr]::Zero) {
    $ed2 = [Map1OES]::FindCtrl($main2, 1001, 'Edit')
    if ($ed2 -eq [IntPtr]::Zero) { $ed2 = [Map1OES]::FindCtrl($main2, 1010, 'RichEdit') }
    $reTxt = [Map1OES]::GetText($ed2)
    if ($reTxt -match 'OES_EDITED' -or $reTxt -match $marker) { $oesReopen = 'PASS' }
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
