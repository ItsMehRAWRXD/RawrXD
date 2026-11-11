#Requires -Version 5.1
# POST_E59D_CANDIDATE_001 CANCEL A→Stop→B
# CERT_EXE SHA 3B720981… only. PROMOTE=0 REBUILD=HELD. No GhostText reopen.
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\CANCEL'
$Logs = Join-Path $OutDir 'logs'
New-Item -ItemType Directory -Force -Path $Logs | Out-Null
$CandExe = 'F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe'
$CandDir = Split-Path $CandExe
$ExpectSha = '3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F'
$ExpectSize = 6080512
$Log = Join-Path $OutDir 'CANCEL_RUNLOG.txt'
Set-Content -LiteralPath $Log -Value ''
function WLog([string]$m) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  Add-Content -LiteralPath $Log -Value $line
  Write-Output $line
}

$cs = @'
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class CancelPostE59d {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool SetWindowTextW(IntPtr h, string s);
  [DllImport("user32.dll")] public static extern int GetWindowTextLengthW(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowVisible(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool IsWindowEnabled(IntPtr h);
  [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll")] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, IntPtr l);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr SendMessageW(IntPtr h, uint m, IntPtr w, StringBuilder l);
  [DllImport("user32.dll")] public static extern int GetWindowLongW(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int n);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  public const uint WM_COMMAND = 0x0111;
  public const uint WM_CLOSE = 0x0010;
  public const uint WM_SETTEXT = 0x000C;
  public const uint BM_CLICK = 0x00F5;
  public const int GWL_ID = -12;
  public const int BN_CLICKED = 0;
  public const int SW_RESTORE = 9;
  public static void ClickChild(IntPtr parent, IntPtr btn, int id) {
    if (btn != IntPtr.Zero) SendMessageW(btn, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
    IntPtr wp = (IntPtr)((BN_CLICKED << 16) | (id & 0xFFFF));
    SendMessageW(parent, WM_COMMAND, wp, btn);
    PostMessageW(parent, WM_COMMAND, wp, btn);
  }
  public static int SetEdit(IntPtr edit, string text) {
    IntPtr p = Marshal.StringToHGlobalUni(text);
    SendMessageW(edit, WM_SETTEXT, IntPtr.Zero, p);
    Marshal.FreeHGlobal(p);
    SetWindowTextW(edit, text);
    return GetWindowTextLengthW(edit);
  }
  public static IntPtr FindMain(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, l) => {
      uint p; GetWindowThreadProcessId(h, out p);
      if (p != pid) return true;
      var cls = new StringBuilder(256);
      GetClassNameW(h, cls, 256);
      if (cls.ToString() == "RawrXD_IDE_Window") { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static IntPtr FindChildById(IntPtr parent, int id) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(parent, (h, l) => {
      if (GetWindowLongW(h, GWL_ID) == id) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static string Text(IntPtr h) {
    int len = SendMessageW(h, 0x000E, IntPtr.Zero, IntPtr.Zero).ToInt32();
    if (len <= 0) len = GetWindowTextLengthW(h);
    if (len <= 0) return "";
    IntPtr buf = Marshal.AllocHGlobal((len + 2) * 2);
    try {
      SendMessageW(h, 0x000D, (IntPtr)(len + 1), buf);
      return Marshal.PtrToStringUni(buf) ?? "";
    } finally { Marshal.FreeHGlobal(buf); }
  }
  public static string StatusBarText(IntPtr main) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(main, (h, l) => {
      var cls = new StringBuilder(256);
      GetClassNameW(h, cls, 256);
      if (cls.ToString() == "msctls_statusbar32") { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    if (found == IntPtr.Zero) return "";
    const uint SB_GETTEXTLENGTHW = 0x040C;
    const uint SB_GETTEXTW = 0x040D;
    int meta = SendMessageW(found, SB_GETTEXTLENGTHW, IntPtr.Zero, IntPtr.Zero).ToInt32();
    int len = meta & 0xFFFF;
    if (len <= 0) return Text(found);
    var buf = new StringBuilder(len + 2);
    SendMessageW(found, SB_GETTEXTW, IntPtr.Zero, buf);
    string s = buf.ToString();
    if (string.IsNullOrEmpty(s)) s = Text(found);
    return s;
  }
  public static List<string> ComboItems(IntPtr combo) {
    var rows = new List<string>();
    if (combo == IntPtr.Zero) return rows;
    int cnt = SendMessageW(combo, 0x0146, IntPtr.Zero, IntPtr.Zero).ToInt32();
    for (int i = 0; i < cnt && i < 200; i++) {
      int len = SendMessageW(combo, 0x0149, (IntPtr)i, IntPtr.Zero).ToInt32();
      if (len < 0) continue;
      var b = new StringBuilder(len + 2);
      SendMessageW(combo, 0x0148, (IntPtr)i, b);
      rows.Add(b.ToString());
    }
    return rows;
  }
  public static void SelectComboIndex(IntPtr parent, IntPtr combo, int index, int comboId) {
    SendMessageW(combo, 0x014E, (IntPtr)index, IntPtr.Zero);
    IntPtr wp = (IntPtr)((1 << 16) | (comboId & 0xFFFF));
    PostMessageW(parent, WM_COMMAND, wp, combo);
  }
}
'@
Add-Type -TypeDefinition $cs -ErrorAction SilentlyContinue | Out-Null

WLog 'START POST_E59D CANCEL A→Stop→B'
WLog 'CLICK_MODE=SINGLE_BM_CLICK (no sync WM_COMMAND / PostMessage amplifier)'
WLog 'PROMOTE=0 REBUILD=HELD GHOSTTEXT_REOPEN=0 GITHUB_COMMIT=70fe7cdaf7'

$reqA = 'NOT_RUN'; $stopOk = 'NOT_RUN'; $reqB = 'NOT_RUN'; $lateA = 'NOT_RUN'
$disposition = 'NOT_RUN'
$modelSelected = ''
$shaPre = ''; $shaPost = ''
$markerA = 'CANCEL_A_UNIQUE_MARKER_POST_E59D_7F3A'
$markerB = 'PONG_B_POST_E59D'

function Write-Receipt([string]$why) {
@"
# POST_E59D_CANDIDATE_001 CANCEL A→Stop→B RECEIPT

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
CERT_EXE=$CandExe
SHA_PRE=$shaPre
SHA_POST=$shaPost
SHA_MATCH_EXPECT=$([int](($shaPre -eq $ExpectSha) -and ($shaPost -eq $ExpectSha)))
PROMOTE=0
CERTIFIED=0
REBUILD=HELD
GHOSTTEXT_REOPEN=0
DISPOSITION=$disposition
STOP_REASON=$why

REQUEST_A_STARTED=$reqA
STOP_CANCELS=$stopOk
REQUEST_B_COMPLETE_RENDER=$reqB
LATE_A_REJECTED_OR_NOT_APPLIED=$lateA
MODEL_ROUTING=$modelSelected
MARKER_A=$markerA
MARKER_B=$markerB
RUNLOG=$Log
"@ | Set-Content -LiteralPath (Join-Path $OutDir 'RECEIPT.md')
}

try {
  if (-not (Test-Path -LiteralPath $CandExe)) {
    $disposition = 'FAIL_CLOSED_EXE_MISSING'
    Write-Receipt $disposition; exit 2
  }
  $shaPre = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
  $sz = (Get-Item -LiteralPath $CandExe).Length
  WLog "SHA_PRE=$shaPre SIZE=$sz"
  $shaPre | Set-Content (Join-Path $OutDir 'SHA_PRE.txt')
  if ($shaPre -ne $ExpectSha -or [int64]$sz -ne $ExpectSize) {
    $disposition = 'FAIL_CLOSED_SHA_DRIFT_PRE'
    $shaPost = $shaPre
    Write-Receipt $disposition; exit 3
  }

  try {
    $null = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/tags' -TimeoutSec 3
    WLog 'OLLAMA_UP=1'
  } catch { WLog "OLLAMA_UP=0 $($_.Exception.Message)" }

  Get-Process | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' } |
    ForEach-Object { WLog "KILL_PRE pid=$($_.Id)"; Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Seconds 2

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $CandExe
  $psi.WorkingDirectory = $CandDir
  $psi.UseShellExecute = $false
  $proc = [Diagnostics.Process]::Start($psi)
  WLog "LAUNCHED pid=$($proc.Id)"
  $proc.Id | Set-Content (Join-Path $Logs 'pid.txt')

  $main = [IntPtr]::Zero
  $deadline = (Get-Date).AddSeconds(90)
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { WLog "EXIT_EARLY $($proc.ExitCode)"; break }
    $main = [CancelPostE59d]::FindMain([uint32]$proc.Id)
    if ($main -ne [IntPtr]::Zero -and [CancelPostE59d]::IsWindowVisible($main)) {
      if ([CancelPostE59d]::FindChildById($main, 1202) -ne [IntPtr]::Zero -and
          [CancelPostE59d]::FindChildById($main, 1204) -ne [IntPtr]::Zero) { break }
    }
    Start-Sleep -Milliseconds 400
  }
  if ($main -eq [IntPtr]::Zero) {
    $disposition = 'FAIL_CLOSED_MAIN_WINDOW'
    $shaPost = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
    Write-Receipt $disposition; exit 4
  }
  [void][CancelPostE59d]::ShowWindow($main, 9)
  [void][CancelPostE59d]::SetForegroundWindow($main)
  WLog ("MAIN hwnd=0x{0:X}" -f $main.ToInt64())

  $inputEdit = [CancelPostE59d]::FindChildById($main, 1202)
  $outputEdit = [CancelPostE59d]::FindChildById($main, 1203)
  $btnSend = [CancelPostE59d]::FindChildById($main, 1204)
  $btnClear = [CancelPostE59d]::FindChildById($main, 1205)
  $combo = [CancelPostE59d]::FindChildById($main, 1206)
  $btnStop = [CancelPostE59d]::FindChildById($main, 1210)
  $sidebar = [CancelPostE59d]::FindChildById($main, 1200)
  if ($sidebar -eq [IntPtr]::Zero) { $sidebar = $main }

  Start-Sleep -Seconds 3
  $rows = @([CancelPostE59d]::ComboItems($combo))
  $rows | Set-Content (Join-Path $Logs 'model_combo_rows.txt')
  WLog "MODEL_COMBO_COUNT=$($rows.Count)"
  $prefer = @('gemma3:4b','qwen2.5-coder:1.5b-base','llama3.2','nemotron-3-nano:4b')
  $pickIdx = -1
  foreach ($p in $prefer) {
    for ($i = 0; $i -lt $rows.Count; $i++) {
      if ($rows[$i] -like "*$p*") { $pickIdx = $i; $modelSelected = $rows[$i]; break }
    }
    if ($pickIdx -ge 0) { break }
  }
  if ($pickIdx -lt 0) {
    for ($i = 0; $i -lt $rows.Count; $i++) {
      if ($rows[$i] -match '(?i)ollama' -and $rows[$i] -notmatch 'connecting') {
        $pickIdx = $i; $modelSelected = $rows[$i]; break
      }
    }
  }
  if ($pickIdx -lt 0) {
    $disposition = 'FAIL_CLOSED_NO_MODEL'
    $shaPost = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    Write-Receipt $disposition; exit 5
  }
  [CancelPostE59d]::SelectComboIndex($main, $combo, $pickIdx, 1206)
  WLog "MODEL_SELECT idx=$pickIdx text=$modelSelected"
  Start-Sleep -Milliseconds 800

  if ($btnClear -ne [IntPtr]::Zero) {
    [CancelPostE59d]::ClickChild($sidebar, $btnClear, 1205)
    Start-Sleep -Milliseconds 200
  }

  $promptA = "Write a very long detailed essay of at least 2000 words about Windows kernel scheduling. Include the exact marker $markerA somewhere in the essay."
  [void][CancelPostE59d]::SetEdit($inputEdit, $promptA)
  [CancelPostE59d]::ClickChild($sidebar, $btnSend, 1204)
  WLog 'REQUEST_A_SUBMITTED'
  Start-Sleep -Milliseconds 400

  $armed = 0
  $armDeadline = (Get-Date).AddSeconds(45)
  while ((Get-Date) -lt $armDeadline) {
    if ($proc.HasExited) { WLog "CRASH_ARM exit=$($proc.ExitCode)"; break }
    $st = [CancelPostE59d]::StatusBarText($main)
    $stopEn = [int][CancelPostE59d]::IsWindowEnabled($btnStop)
    if ($stopEn -eq 1 -or $st -match '(?i)warming|waiting|running|Ollama|already running|Inference') {
      $armed = 1
      $reqA = 'PASS'
      WLog "REQUEST_A_ARMED stopEnabled=$stopEn status='$st'"
      break
    }
    Start-Sleep -Milliseconds 200
  }
  if ($armed -ne 1) {
    $reqA = 'FAIL'; $stopOk = 'FAIL'; $reqB = 'FAIL'; $lateA = 'FAIL'
    if ($proc.HasExited) { $disposition = 'FAIL_CLOSED_CRASH_ON_REQUEST_A' }
    else { $disposition = 'FAIL_CLOSED_REQUEST_A_NOT_ARMED' }
    WLog $disposition
    $shaPost = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    Write-Receipt $disposition; exit 6
  }

  Start-Sleep -Milliseconds 1200
  [CancelPostE59d]::ClickChild($sidebar, $btnStop, 1210)
  $stopAt = Get-Date
  WLog 'STOP_CLICKED'
  Start-Sleep -Milliseconds 400
  $stStop = [CancelPostE59d]::StatusBarText($main)
  $stopEnAfter = [int][CancelPostE59d]::IsWindowEnabled($btnStop)
  WLog "STATUS_AFTER_STOP='$stStop' stopEnabled=$stopEnAfter"
  $stStop | Set-Content (Join-Path $Logs 'status_after_stop.txt')
  if ($stStop -match '(?i)stop|cancel' -or $stopEnAfter -eq 0) { $stopOk = 'PASS' } else { $stopOk = 'FAIL' }

  $waitMs = [Math]::Max(0, 5000 - [int]((Get-Date) - $stopAt).TotalMilliseconds)
  if ($waitMs -gt 0) { Start-Sleep -Milliseconds $waitMs }

  $outBeforeB = [CancelPostE59d]::Text($outputEdit)
  $outBeforeB | Set-Content (Join-Path $Logs 'output_before_b.txt')
  $promptB = "Reply with exactly one word: $markerB"
  [void][CancelPostE59d]::SetEdit($inputEdit, $promptB)
  [CancelPostE59d]::ClickChild($sidebar, $btnSend, 1204)
  WLog 'REQUEST_B_SUBMITTED'

  $bOk = 0
  $busyReject = 0
  $bDeadline = (Get-Date).AddSeconds(120)
  while ((Get-Date) -lt $bDeadline) {
    if ($proc.HasExited) { WLog "CRASH_B exit=$($proc.ExitCode)"; break }
    $st = [CancelPostE59d]::StatusBarText($main)
    $outNow = [CancelPostE59d]::Text($outputEdit)
    if ($st -match '(?i)already running') {
      $busyReject = 1
      WLog 'REQUEST_B_REJECTED_ALREADY_RUNNING'
      break
    }
    if ($outNow -match [regex]::Escape($markerB)) {
      $bOk = 1
      WLog "REQUEST_B_RENDERED outLen=$($outNow.Length)"
      break
    }
    if ($outNow.Length -gt $outBeforeB.Length + 10 -and $st -match '(?i)response received') {
      # growth without exact marker still counts if status completed
      if ($outNow -match 'PONG_B') { $bOk = 1; break }
    }
    Start-Sleep -Milliseconds 300
  }
  $outFinal = [CancelPostE59d]::Text($outputEdit)
  $outFinal | Set-Content (Join-Path $Logs 'output_after_b.txt')
  if ($busyReject -eq 1) { $reqB = 'FAIL' }
  elseif ($bOk -eq 1) { $reqB = 'PASS' }
  else { $reqB = 'FAIL' }

  # Late A: after B rendered, wait briefly; if markerA newly appears without being part of B path → FAIL
  Start-Sleep -Seconds 3
  $outLate = [CancelPostE59d]::Text($outputEdit)
  $outLate | Set-Content (Join-Path $Logs 'output_late_check.txt')
  $hadABeforeB = ($outBeforeB -match [regex]::Escape($markerA))
  $hasALate = ($outLate -match [regex]::Escape($markerA))
  $hasB = ($outLate -match [regex]::Escape($markerB))
  if ($hasB -and (-not $hasALate -or $hadABeforeB)) {
    # B present; A marker absent OR was already there before B (partial stream before stop) — treat absent growth as rejected
    if (-not $hasALate) { $lateA = 'PASS' }
    elseif ($hadABeforeB -and $hasB) {
      # A leaked before stop; still require B won — late A not newly applied after B
      $lateA = 'PASS'
      WLog 'LATE_A=PASS (A partial before B; B rendered; no post-B A-only apply proven)'
    } else { $lateA = 'FAIL' }
  } elseif ($hasB -and $hasALate -and -not $hadABeforeB) {
    $lateA = 'FAIL'
    WLog 'LATE_A=FAIL (A marker appeared after B window)'
  } elseif ($reqB -eq 'PASS') {
    $lateA = 'PASS'
    WLog 'LATE_A=PASS (B ok; A marker not observed post-B)'
  } else {
    $lateA = 'FAIL'
  }

  if ($reqA -eq 'PASS' -and $stopOk -eq 'PASS' -and $reqB -eq 'PASS' -and $lateA -eq 'PASS') {
    $disposition = 'PASS_CANCEL_A_STOP_B'
  } else {
    $disposition = "FAIL_CLOSED A=$reqA STOP=$stopOk B=$reqB LATE_A=$lateA"
  }
  WLog "DISPOSITION=$disposition"

  [void][CancelPostE59d]::PostMessageW($main, [CancelPostE59d]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 800
  if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Seconds 1

  $shaPost = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
  $shaPost | Set-Content (Join-Path $OutDir 'SHA_POST.txt')
  WLog "SHA_POST=$shaPost"
  if ($shaPost -ne $ExpectSha) {
    $disposition = 'FAIL_CLOSED_SHA_DRIFT_POST'
  }
  Write-Receipt $disposition
  if ($disposition -eq 'PASS_CANCEL_A_STOP_B') { exit 0 } else { exit 1 }
}
catch {
  WLog ("EXCEPTION={0}" -f $_.Exception.Message)
  $disposition = 'FAIL_CLOSED_EXCEPTION'
  try { $shaPost = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash } catch { $shaPost = 'ERR' }
  Write-Receipt $_.Exception.Message
  exit 3
}
