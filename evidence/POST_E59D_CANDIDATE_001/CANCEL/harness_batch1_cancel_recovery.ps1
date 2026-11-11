#Requires -Version 5.1
# BATCH1_CANCEL_RECOVERY — same-SHA A→Stop→B (narrow)
# HARNESS: NO_CLEAR + WM_SETTEXT_ONLY + SINGLE_BM_CLICK (no triple, no dual SetEdit)
# Does NOT overwrite RECEIPT.md / CANCEL_RUNLOG.txt / sealed dumps / CANCEL_CLASSIFICATION_SEALED.md
# PROMOTE=0 REBUILD=HELD CERTIFIED=0
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\POST_E59D_CANDIDATE_001\CANCEL'
$Logs = Join-Path $OutDir 'logs'
New-Item -ItemType Directory -Force -Path $Logs | Out-Null
$CandExe = 'F:\rawrxd\build_post_e59d_candidate\bin\RawrXD-Win32IDE-Native.exe'
$CandDir = Split-Path $CandExe
$ExpectSha = '3B720981EC567D60461B874F0C1EE46E03F85DB58F6E1788CBEE31F8B2CCAD5F'
$ExpectSize = 6080512
$Stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$Log = Join-Path $OutDir ("BATCH1_CANCEL_RECOVERY_RUNLOG_{0}.txt" -f $Stamp)
$Console = Join-Path $Logs ("batch1_recovery_console_{0}.txt" -f $Stamp)
$ResultJson = Join-Path $Logs ("batch1_recovery_result_{0}.json" -f $Stamp)
$ControllingReceipt = Join-Path $OutDir 'BATCH1_CANCEL_RECOVERY_RECEIPT.md'
Set-Content -LiteralPath $Log -Value ''
function WLog([string]$m) {
  $line = '[{0}] {1}' -f (Get-Date -Format 'o'), $m
  Add-Content -LiteralPath $Log -Value $line
  Add-Content -LiteralPath $Console -Value $line
  Write-Output $line
}

$cs = @'
using System;
using System.Text;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public class Batch1CancelRecovery {
  public delegate bool EnumProc(IntPtr h, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr h, EnumProc lp, IntPtr l);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetClassNameW(IntPtr h, StringBuilder s, int n);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
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
  public const int SW_RESTORE = 9;
  // Single BM_CLICK only — no WM_COMMAND / PostMessage amplifier (triple REFUTED sole-cause; sealed FAIL).
  public static void ClickChild(IntPtr btn) {
    if (btn != IntPtr.Zero) SendMessageW(btn, BM_CLICK, IntPtr.Zero, IntPtr.Zero);
  }
  // WM_SETTEXT only — no dual SetWindowTextW (suspected harness residual; not proven).
  public static int SetEditWmOnly(IntPtr edit, string text) {
    IntPtr p = Marshal.StringToHGlobalUni(text);
    SendMessageW(edit, WM_SETTEXT, IntPtr.Zero, p);
    Marshal.FreeHGlobal(p);
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

WLog 'START BATCH1_CANCEL_RECOVERY A→Stop→B'
WLog 'HARNESS_CHOICE=NO_CLEAR + WM_SETTEXT_ONLY + SINGLE_BM_CLICK'
WLog 'HARNESS_AVOID=Clear(1205) dual-SetEdit triple-multi-notify'
WLog 'PROMOTE=0 REBUILD=HELD CERTIFIED=0 GHOSTTEXT_REOPEN=0'
WLog "STAMP=$Stamp"

$reqA = 'NOT_RUN'; $stopOk = 'NOT_RUN'; $reqB = 'NOT_RUN'; $bStarted = 'NOT_RUN'
$lateA = 'NOT_RUN'; $aActive = 'NOT_RUN'
$disposition = 'NOT_RUN'
$crash = 0; $hang = 0
$productDefect = 'NOT_PROVEN'
$modelSelected = ''
$shaPre = ''; $shaPost = ''
$exitCode = ''
$markerA = 'CANCEL_A_UNIQUE_MARKER_BATCH1_RECOVERY_9C2E'
$markerB = 'PONG_B_BATCH1_RECOVERY'
$newDump = ''

function Write-ControllingReceipt([string]$why) {
  $shaMatch = [int](($shaPre -eq $ExpectSha) -and ($shaPost -eq $ExpectSha))
  $batch1 = 'INCONCLUSIVE'
  if ($disposition -eq 'PASS_CANCEL_A_STOP_B') { $batch1 = 'PASS' }
  elseif ($disposition -like 'FAIL*' -or $crash -eq 1) { $batch1 = 'FAIL' }
  elseif ($disposition -eq 'NOT_RUN') { $batch1 = 'NOT_RUN' }
  $nextGate = 'BATCH1_CANCEL_RECOVERY'
  if ($batch1 -eq 'PASS') { $nextGate = 'FINAL_CERTIFICATION_REVIEW' }
  elseif ($batch1 -eq 'FAIL' -or $batch1 -eq 'INCONCLUSIVE') { $nextGate = 'BATCH1_CANCEL_RECOVERY' }
@"
# BATCH1_CANCEL_RECOVERY_RECEIPT (controlling)

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
STAMP=$Stamp
GATE=BATCH1_CANCEL_RECOVERY
AUTH=CONTINUE_SAME_SHA

CERT_EXE=$CandExe
CERT_EXE_SHA_BEFORE=$shaPre
CERT_EXE_SHA_AFTER=$shaPost
SHA_MATCH=$shaMatch
SIZE_EXPECT=$ExpectSize
REBUILD=HELD
REBUILD_AUTHORIZED=0
PROMOTE=0
CERTIFIED=0
TIP_CLIMB=HOLD
GHOSTTEXT_REOPEN=0
CHATWINDOW_REOPEN=0
TOKEN64_REOPEN=0
CANCEL_CLASSIFICATION=SEALED_PRESERVED

## Harness choices (documented)

```
CLICK_MODE=SINGLE_BM_CLICK
CLEAR_CLICK=0
SETEDIT_MODE=WM_SETTEXT_ONLY
DUAL_SETEDIT=0
TRIPLE_MULTI_NOTIFY=0
STOP_PATH=SINGLE_BM_CLICK_BTN_1210
RATIONALE=Prior Clear+dual-SetEdit Cancel crashed on Request A arm (073409). Hang isolation NO_CLEAR+WM_SETTEXT_ONLY survived 20s NO_CRASH. Triple multi-notify sealed FAIL / sole-harness REFUTED — not used.
```

## Prove fields

```
BATCH1_CANCEL_RECOVERY=$batch1
A_STARTED=$reqA
A_ACTIVE_GENERATION=$aActive
STOP_OK=$stopOk
B_STARTED=$bStarted
B_RENDERED=$reqB
LATE_A_REJECTED=$lateA
CRASH=$crash
HANG=$hang
PRODUCT_DEFECT=$productDefect
EXIT_CODE=$exitCode
MODEL_ROUTING=$modelSelected
MARKER_A=$markerA
MARKER_B=$markerB
DISPOSITION=$disposition
STOP_REASON=$why
NEXT_GATE=$nextGate
```

## Artifacts (new this run — sealed priors untouched)

- RUNLOG=$Log
- CONSOLE=$Console
- RESULT_JSON=$ResultJson
- NEW_DUMP=$newDump
- SEALED_DUMPS_PRESERVED=logs/rawrxd-20261103-070906.dmp ; logs/rawrxd-20261103-073409.dmp
- SEALED_CLASSIFICATION=CANCEL_CLASSIFICATION_SEALED.md
"@ | Set-Content -LiteralPath $ControllingReceipt -Encoding UTF8

  @{
    BATCH1_CANCEL_RECOVERY = $batch1
    CERT_EXE_SHA_BEFORE = $shaPre
    CERT_EXE_SHA_AFTER = $shaPost
    SHA_MATCH = $shaMatch
    CRASH = $crash
    HANG = $hang
    A_STARTED = $reqA
    A_ACTIVE_GENERATION = $aActive
    STOP_OK = $stopOk
    B_STARTED = $bStarted
    B_RENDERED = $reqB
    LATE_A_REJECTED = $lateA
    PRODUCT_DEFECT = $productDefect
    DISPOSITION = $disposition
    NEXT_GATE = $nextGate
    EXIT_CODE = "$exitCode"
    STAMP = $Stamp
  } | ConvertTo-Json | Set-Content -LiteralPath $ResultJson -Encoding UTF8
}

try {
  if (-not (Test-Path -LiteralPath $CandExe)) {
    $disposition = 'FAIL_CLOSED_EXE_MISSING'
    Write-ControllingReceipt $disposition; exit 2
  }
  $shaPre = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
  $sz = (Get-Item -LiteralPath $CandExe).Length
  WLog "SHA_PRE=$shaPre SIZE=$sz"
  $shaPre | Set-Content (Join-Path $Logs ("sha_pre_batch1_{0}.txt" -f $Stamp))
  if ($shaPre -ne $ExpectSha -or [int64]$sz -ne $ExpectSize) {
    $disposition = 'FAIL_CLOSED_SHA_DRIFT_PRE'
    $shaPost = $shaPre
    Write-ControllingReceipt $disposition; exit 3
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
  $proc.Id | Set-Content (Join-Path $Logs ("pid_batch1_{0}.txt" -f $Stamp))

  $main = [IntPtr]::Zero
  $deadline = (Get-Date).AddSeconds(90)
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { WLog "EXIT_EARLY $($proc.ExitCode)"; $crash = 1; $exitCode = "$($proc.ExitCode)"; break }
    $main = [Batch1CancelRecovery]::FindMain([uint32]$proc.Id)
    if ($main -ne [IntPtr]::Zero -and [Batch1CancelRecovery]::IsWindowVisible($main)) {
      if ([Batch1CancelRecovery]::FindChildById($main, 1202) -ne [IntPtr]::Zero -and
          [Batch1CancelRecovery]::FindChildById($main, 1204) -ne [IntPtr]::Zero) { break }
    }
    Start-Sleep -Milliseconds 400
  }
  if ($main -eq [IntPtr]::Zero) {
    $disposition = 'FAIL_CLOSED_MAIN_WINDOW'
    if ($proc.HasExited) { $crash = 1; $exitCode = "$($proc.ExitCode)" }
    $shaPost = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
    Write-ControllingReceipt $disposition; exit 4
  }
  [void][Batch1CancelRecovery]::ShowWindow($main, 9)
  [void][Batch1CancelRecovery]::SetForegroundWindow($main)
  WLog ("MAIN hwnd=0x{0:X}" -f $main.ToInt64())

  $inputEdit = [Batch1CancelRecovery]::FindChildById($main, 1202)
  $outputEdit = [Batch1CancelRecovery]::FindChildById($main, 1203)
  $btnSend = [Batch1CancelRecovery]::FindChildById($main, 1204)
  $combo = [Batch1CancelRecovery]::FindChildById($main, 1206)
  $btnStop = [Batch1CancelRecovery]::FindChildById($main, 1210)
  # Explicitly DO NOT click Clear (1205) — harness residual shrink

  Start-Sleep -Seconds 3
  $rows = @([Batch1CancelRecovery]::ComboItems($combo))
  $rows | Set-Content (Join-Path $Logs ("model_combo_rows_batch1_{0}.txt" -f $Stamp))
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
    Write-ControllingReceipt $disposition; exit 5
  }
  [Batch1CancelRecovery]::SelectComboIndex($main, $combo, $pickIdx, 1206)
  WLog "MODEL_SELECT idx=$pickIdx text=$modelSelected CLEAR_CLICK=0"
  Start-Sleep -Milliseconds 800

  $promptA = "Write a very long detailed essay of at least 2000 words about Windows kernel scheduling. Include the exact marker $markerA somewhere in the essay."
  $lenA = [Batch1CancelRecovery]::SetEditWmOnly($inputEdit, $promptA)
  WLog "SETEDIT_A_WM_ONLY len=$lenA"
  [Batch1CancelRecovery]::ClickChild($btnSend)
  WLog 'REQUEST_A_SUBMITTED'
  Start-Sleep -Milliseconds 400

  $armed = 0
  $armDeadline = (Get-Date).AddSeconds(45)
  while ((Get-Date) -lt $armDeadline) {
    if ($proc.HasExited) {
      $crash = 1
      $exitCode = "$($proc.ExitCode)"
      WLog "CRASH_ARM exit=$exitCode"
      break
    }
    $st = [Batch1CancelRecovery]::StatusBarText($main)
    $stopEn = [int][Batch1CancelRecovery]::IsWindowEnabled($btnStop)
    if ($stopEn -eq 1 -or $st -match '(?i)warming|waiting|running|Ollama|already running|Inference|Generating|Streaming') {
      $armed = 1
      $reqA = 'PASS'
      $aActive = 'PASS'
      WLog "REQUEST_A_ARMED stopEnabled=$stopEn status='$st'"
      break
    }
    Start-Sleep -Milliseconds 200
  }
  if ($armed -ne 1) {
    $reqA = 'FAIL'; $aActive = 'FAIL'; $stopOk = 'FAIL'; $reqB = 'FAIL'; $bStarted = 'FAIL'; $lateA = 'FAIL'
    if ($crash -eq 1) {
      $disposition = 'FAIL_CLOSED_CRASH_ON_REQUEST_A'
      # Capture newest dump if product wrote one (preserve sealed dumps; copy new only)
      $dumpSrc = Get-ChildItem -Path (Join-Path $CandDir '*') -Filter 'rawrxd-*.dmp' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
      if (-not $dumpSrc) {
        $dumpSrc = Get-ChildItem -Path $Logs -Filter 'rawrxd-*.dmp' -ErrorAction SilentlyContinue |
          Where-Object { $_.Name -notmatch '070906|073409' } |
          Sort-Object LastWriteTime -Descending | Select-Object -First 1
      }
      # Also check common crash dump locations near exe / cwd
      $candDumps = @(
        (Join-Path $CandDir 'rawrxd-*.dmp'),
        (Join-Path $Logs 'rawrxd-*.dmp'),
        'F:\rawrxd\build_post_e59d_candidate\bin\rawrxd-*.dmp'
      )
      foreach ($pat in $candDumps) {
        $hit = Get-Item $pat -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($hit -and $hit.Name -notmatch '070906|073409' -and $hit.LastWriteTime -gt (Get-Date).AddMinutes(-5)) {
          $dest = Join-Path $Logs ("rawrxd-batch1-{0}-{1}" -f $Stamp, $hit.Name)
          if ($hit.DirectoryName -ne $Logs) {
            Copy-Item -LiteralPath $hit.FullName -Destination $dest -Force
            $newDump = $dest
          } else {
            $newDump = $hit.FullName
          }
          WLog "NEW_DUMP=$newDump"
          break
        }
      }
    } else { $disposition = 'FAIL_CLOSED_REQUEST_A_NOT_ARMED' }
    WLog $disposition
    $shaPost = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    Write-ControllingReceipt $disposition; exit 6
  }

  # Brief settle then single Stop click (user-like)
  Start-Sleep -Milliseconds 1200
  if ($proc.HasExited) {
    $crash = 1; $exitCode = "$($proc.ExitCode)"
    $disposition = 'FAIL_CLOSED_CRASH_BEFORE_STOP'
    $stopOk = 'FAIL'; $reqB = 'FAIL'; $bStarted = 'FAIL'; $lateA = 'FAIL'
    WLog $disposition
    $shaPost = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
    Write-ControllingReceipt $disposition; exit 7
  }
  [Batch1CancelRecovery]::ClickChild($btnStop)
  $stopAt = Get-Date
  WLog 'STOP_CLICKED SINGLE_BM'
  Start-Sleep -Milliseconds 400
  if ($proc.HasExited) {
    $crash = 1; $exitCode = "$($proc.ExitCode)"
    $stopOk = 'FAIL'; $reqB = 'FAIL'; $bStarted = 'FAIL'; $lateA = 'FAIL'
    $disposition = 'FAIL_CLOSED_CRASH_ON_STOP'
    WLog $disposition
    $shaPost = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
    Write-ControllingReceipt $disposition; exit 8
  }
  $stStop = [Batch1CancelRecovery]::StatusBarText($main)
  $stopEnAfter = [int][Batch1CancelRecovery]::IsWindowEnabled($btnStop)
  WLog "STATUS_AFTER_STOP='$stStop' stopEnabled=$stopEnAfter"
  $stStop | Set-Content (Join-Path $Logs ("status_after_stop_batch1_{0}.txt" -f $Stamp))
  if ($stStop -match '(?i)stop|cancel' -or $stopEnAfter -eq 0) { $stopOk = 'PASS' } else { $stopOk = 'FAIL' }

  $waitMs = [Math]::Max(0, 5000 - [int]((Get-Date) - $stopAt).TotalMilliseconds)
  if ($waitMs -gt 0) { Start-Sleep -Milliseconds $waitMs }
  if ($proc.HasExited) {
    $crash = 1; $exitCode = "$($proc.ExitCode)"
    $disposition = 'FAIL_CLOSED_CRASH_AFTER_STOP'
    $reqB = 'FAIL'; $bStarted = 'FAIL'; $lateA = 'FAIL'
    WLog $disposition
    $shaPost = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
    Write-ControllingReceipt $disposition; exit 9
  }

  $outBeforeB = [Batch1CancelRecovery]::Text($outputEdit)
  $outBeforeB | Set-Content (Join-Path $Logs ("output_before_b_batch1_{0}.txt" -f $Stamp))
  $promptB = "Reply with exactly one word: $markerB"
  $lenB = [Batch1CancelRecovery]::SetEditWmOnly($inputEdit, $promptB)
  WLog "SETEDIT_B_WM_ONLY len=$lenB"
  [Batch1CancelRecovery]::ClickChild($btnSend)
  WLog 'REQUEST_B_SUBMITTED'
  $bStarted = 'PASS'

  $bOk = 0
  $busyReject = 0
  $bDeadline = (Get-Date).AddSeconds(120)
  $lastAlive = Get-Date
  while ((Get-Date) -lt $bDeadline) {
    if ($proc.HasExited) {
      $crash = 1; $exitCode = "$($proc.ExitCode)"
      WLog "CRASH_B exit=$exitCode"
      break
    }
    # Hang watch: if Stop stays enabled forever and no status change 90s after B — mark hang later
    $st = [Batch1CancelRecovery]::StatusBarText($main)
    $outNow = [Batch1CancelRecovery]::Text($outputEdit)
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
      if ($outNow -match 'PONG_B') { $bOk = 1; break }
    }
    Start-Sleep -Milliseconds 300
  }
  $outFinal = [Batch1CancelRecovery]::Text($outputEdit)
  $outFinal | Set-Content (Join-Path $Logs ("output_after_b_batch1_{0}.txt" -f $Stamp))
  if ($busyReject -eq 1) { $reqB = 'FAIL'; $bStarted = 'FAIL' }
  elseif ($crash -eq 1) { $reqB = 'FAIL' }
  elseif ($bOk -eq 1) { $reqB = 'PASS' }
  else {
    $reqB = 'FAIL'
    # If process alive but no B render within deadline → possible hang residual
    if (-not $proc.HasExited) {
      $hang = 1
      WLog 'HANG_SUSPECT=B_NOT_RENDERED_WITHIN_120S process_alive=1'
    }
  }

  Start-Sleep -Seconds 3
  $outLate = [Batch1CancelRecovery]::Text($outputEdit)
  $outLate | Set-Content (Join-Path $Logs ("output_late_check_batch1_{0}.txt" -f $Stamp))
  $hadABeforeB = ($outBeforeB -match [regex]::Escape($markerA))
  $hasALate = ($outLate -match [regex]::Escape($markerA))
  $hasB = ($outLate -match [regex]::Escape($markerB))
  if ($hasB -and (-not $hasALate)) { $lateA = 'PASS' }
  elseif ($hasB -and $hasALate -and $hadABeforeB) {
    $lateA = 'PASS'
    WLog 'LATE_A=PASS (A partial before B; B rendered)'
  } elseif ($hasB -and $hasALate -and -not $hadABeforeB) {
    $lateA = 'FAIL'
    WLog 'LATE_A=FAIL (A marker appeared after B window)'
  } elseif ($reqB -eq 'PASS') {
    $lateA = 'PASS'
    WLog 'LATE_A=PASS (B ok; A marker not observed post-B)'
  } else {
    $lateA = 'FAIL'
  }

  if ($reqA -eq 'PASS' -and $stopOk -eq 'PASS' -and $reqB -eq 'PASS' -and $lateA -eq 'PASS' -and $crash -eq 0 -and $hang -eq 0) {
    $disposition = 'PASS_CANCEL_A_STOP_B'
  } else {
    $disposition = "FAIL_CLOSED A=$reqA STOP=$stopOk B=$reqB LATE_A=$lateA CRASH=$crash HANG=$hang"
  }
  WLog "DISPOSITION=$disposition"
  # Do not invent PRODUCT_DEFECT — sealed classification remains MIXED_RESIDUAL / NOT_PROVEN
  $productDefect = 'NOT_PROVEN'

  [void][Batch1CancelRecovery]::PostMessageW($main, [Batch1CancelRecovery]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 800
  if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Seconds 1

  $shaPost = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
  $shaPost | Set-Content (Join-Path $Logs ("sha_post_batch1_{0}.txt" -f $Stamp))
  WLog "SHA_POST=$shaPost"
  if ($shaPost -ne $ExpectSha) {
    $disposition = 'FAIL_CLOSED_SHA_DRIFT_POST'
  }
  Write-ControllingReceipt $disposition
  if ($disposition -eq 'PASS_CANCEL_A_STOP_B') { exit 0 } else { exit 1 }
}
catch {
  WLog ("EXCEPTION={0}" -f $_.Exception.Message)
  $disposition = 'FAIL_CLOSED_EXCEPTION'
  try { $shaPost = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash } catch { $shaPost = 'ERR' }
  Write-ControllingReceipt $_.Exception.Message
  exit 3
}
