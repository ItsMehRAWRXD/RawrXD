#Requires -Version 5.1
# BATCH1_CANCEL_RECOVERY_001 — gates 04-08 / Batch1 10-11 runtime verification
# Tip build only: F:\rawrxd\build_modelroute\bin\Release\RawrXD-Win32IDE-Native.exe
# Do NOT touch seal authority CB34EF4E…  PROMOTE=0 CERTIFIED=0 INVENT_PASS=0
# Fail-closed: NOT_RUN != PASS
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\BATCH1_CANCEL_RECOVERY_001'
$Logs = Join-Path $OutDir 'logs'
New-Item -ItemType Directory -Force -Path $Logs | Out-Null
$TipExe = 'F:\rawrxd\build_modelroute\bin\Release\RawrXD-Win32IDE-Native.exe'
$TipDir = Split-Path $TipExe
$SealAuthoritySha = 'CB34EF4E1A3C964ADEC18F02ABBE605B85CB83F10961BCA6A9DB2D812FC0C6FB'
$Log = Join-Path $OutDir 'CANCEL_RECOVERY_RUNLOG.txt'
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
public class CancelRecov010 {
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
  public const uint WM_COMMAND = 0x0111;
  public const uint WM_CLOSE = 0x0010;
  public const uint WM_SETTEXT = 0x000C;
  public const uint BM_CLICK = 0x00F5;
  public const int GWL_ID = -12;
  public const int BN_CLICKED = 0;
  public const int SW_RESTORE = 9;
  public static void ClickChild(IntPtr parent, IntPtr btn, int id) {
    IntPtr wp = (IntPtr)((BN_CLICKED << 16) | (id & 0xFFFF));
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
    int len = GetWindowTextLengthW(h);
    var b = new StringBuilder(Math.Max(1024, len + 1));
    GetWindowTextW(h, b, b.Capacity);
    return b.ToString();
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

WLog 'START BATCH1_CANCEL_RECOVERY_001 gates 04-08 / Batch1 10-11'
WLog 'PROMOTE=0 CERTIFIED=0 INVENT_PASS=0 SEAL_AUTHORITY_TOUCH=0'

$gate04 = 'NOT_RUN'
$gate05 = 'NOT_RUN'
$gate06 = 'NOT_RUN'
$gate07 = 'NOT_RUN'
$gate08 = 'NOT_RUN'
$disposition = 'NOT_RUN'
$runtimeReached = 0
$requestBAccepted = 0
$requestBResponse = 0
$stopSignalObserved = 0
$busyRejected = 0
$modelSelected = ''
$testedSha = ''
$ollamaUp = 0

function Write-Receipt {
  param([string]$Why)
  @"
# BATCH1_CANCEL_RECOVERY_001 RECEIPT

ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
EXE=$TipExe
TESTED_SHA256=$testedSha
SEAL_AUTHORITY_SHA256=$SealAuthoritySha
SEAL_AUTHORITY_TOUCHED=0
TIP_BUILD=build_modelroute Release RawrXD-Win32IDE-Native
PROMOTE=0
CERTIFIED=0
INVENT_PASS=0
RUNTIME_REACHED=$runtimeReached
DISPOSITION=$disposition
STOP_REASON=$Why

GATE_04_WORKER_CANCELLATION_SIGNAL=$gate04
GATE_05_WORKER_CANCELLATION_CLEANUP=$gate05
GATE_06_INFERENCE_RUNNING_FLAG_RESET=$gate06
GATE_07_REQUEST_B_ADMISSION_AFTER_STOP=$gate07
GATE_08_REQUEST_B_RESPONSE_RENDERING=$gate08
BATCH1_10_CANCELLATION_CLEANUP=$gate05
BATCH1_11_POST_CANCEL_REQUEST_RECOVERY=$gate07

STOP_SIGNAL_OBSERVED=$stopSignalObserved
REQUEST_B_ACCEPTED=$requestBAccepted
REQUEST_B_RESPONSE=$requestBResponse
BUSY_REJECTED=$busyRejected
OLLAMA_UP=$ollamaUp
MODEL_ROUTING=$modelSelected
ASSERT=m_inferenceRunning cleared OR Request B accepted (status not 'already running'); wait<=5s after Stop
FAIL_CLOSED_LAW=NOT_RUN!=PASS
RUNLOG=$Log
"@ | Set-Content -LiteralPath (Join-Path $OutDir 'RECEIPT.md')
  @"
GATE_04=$gate04
GATE_05=$gate05
GATE_06=$gate06
GATE_07=$gate07
GATE_08=$gate08
BATCH1_10=$gate05
BATCH1_11=$gate07
DISPOSITION=$disposition
TESTED_SHA256=$testedSha
RUNTIME_REACHED=$runtimeReached
"@ | Set-Content -LiteralPath (Join-Path $OutDir 'GATE_04_08_SUMMARY.txt')
}

try {
  if (-not (Test-Path -LiteralPath $TipExe)) {
    $disposition = 'FAIL_CLOSED_EXE_MISSING'
    WLog "EXE_MISSING path=$TipExe"
    Write-Receipt $disposition
    exit 2
  }
  $testedSha = (Get-FileHash -LiteralPath $TipExe -Algorithm SHA256).Hash
  WLog "TESTED_SHA256=$testedSha"
  $testedSha | Set-Content -LiteralPath (Join-Path $OutDir 'TESTED_EXE_SHA256.txt')
  if ($testedSha -eq $SealAuthoritySha) {
    WLog 'WARN tested tip SHA equals seal authority SHA — still not replacing seal binary path'
  }

  try {
    $tags = Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/tags' -TimeoutSec 3
    $ollamaUp = 1
    $ollamaModels = @($tags.models | ForEach-Object { $_.name })
    WLog ("OLLAMA_UP=1 models_sample={0}" -f ($ollamaModels[0..([Math]::Min(4, [Math]::Max(0,$ollamaModels.Count-1)))] -join ','))
  } catch {
    $ollamaModels = @()
    WLog ("OLLAMA_UP=0 detail={0}" -f $_.Exception.Message)
  }
  "OLLAMA_UP=$ollamaUp" | Set-Content -LiteralPath (Join-Path $Logs 'ollama_probe.txt')

  Get-Process | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' } |
    ForEach-Object { WLog "KILL_PRE pid=$($_.Id)"; Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Seconds 2

  $psi = New-Object System.Diagnostics.ProcessStartInfo
  $psi.FileName = $TipExe
  $psi.WorkingDirectory = $TipDir
  $psi.UseShellExecute = $false
  $env:RAWRXD_LOG_DIR = $Logs
  $proc = [Diagnostics.Process]::Start($psi)
  WLog "LAUNCHED pid=$($proc.Id)"
  $proc.Id | Set-Content -LiteralPath (Join-Path $Logs 'pid.txt')
  $runtimeReached = 1

  $main = [IntPtr]::Zero
  $deadline = (Get-Date).AddSeconds(90)
  while ((Get-Date) -lt $deadline) {
    if ($proc.HasExited) { WLog "EXIT_EARLY code=$($proc.ExitCode)"; break }
    $main = [CancelRecov010]::FindMain([uint32]$proc.Id)
    if ($main -ne [IntPtr]::Zero -and [CancelRecov010]::IsWindowVisible($main)) {
      $inputProbe = [CancelRecov010]::FindChildById($main, 1202)
      $sendProbe = [CancelRecov010]::FindChildById($main, 1204)
      if ($inputProbe -ne [IntPtr]::Zero -and $sendProbe -ne [IntPtr]::Zero) { break }
    }
    Start-Sleep -Milliseconds 500
  }
  if ($main -eq [IntPtr]::Zero -or -not [CancelRecov010]::IsWindowVisible($main)) {
    $disposition = 'FAIL_CLOSED_MAIN_WINDOW'
    $gate04='FAIL'; $gate05='FAIL'; $gate06='FAIL'; $gate07='FAIL'; $gate08='FAIL'
    WLog $disposition
    Write-Receipt $disposition
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    exit 4
  }
  [void][CancelRecov010]::ShowWindow($main, [CancelRecov010]::SW_RESTORE)
  WLog ("MAIN_READY hwnd=0x{0:X}" -f $main.ToInt64())

  $inputEdit = [CancelRecov010]::FindChildById($main, 1202)
  $outputEdit = [CancelRecov010]::FindChildById($main, 1203)
  $btnSend = [CancelRecov010]::FindChildById($main, 1204)
  $combo = [CancelRecov010]::FindChildById($main, 1206)
  $btnStop = [CancelRecov010]::FindChildById($main, 1210)
  $sidebar = [CancelRecov010]::FindChildById($main, 1200)
  if ($sidebar -eq [IntPtr]::Zero) { $sidebar = $main }

  $waitModelsUntil = (Get-Date).AddSeconds(75)
  $comboRows = @()
  $stableHits = 0
  $prevCount = -1
  while ((Get-Date) -lt $waitModelsUntil -and $combo -ne [IntPtr]::Zero) {
    if ($proc.HasExited) { break }
    $comboRows = @([CancelRecov010]::ComboItems($combo))
    $ollamaHits = @($comboRows | Where-Object { $_ -match '(?i)ollama' -and $_ -notmatch 'connecting' })
    WLog ("MODEL_COMBO_COUNT={0} ollama_rows={1} stableHits={2}" -f $comboRows.Count, $ollamaHits.Count, $stableHits)
    if ($ollamaHits.Count -gt 0) {
      if ($comboRows.Count -eq $prevCount) { $stableHits++ } else { $stableHits = 0 }
      $prevCount = $comboRows.Count
      if ($stableHits -ge 4) { break }
    }
    Start-Sleep -Milliseconds 900
  }
  $comboRows | Set-Content -LiteralPath (Join-Path $Logs 'model_combo_rows.txt')

  if ($combo -ne [IntPtr]::Zero -and $comboRows.Count -gt 0) {
    $preferSub = @('qwen2.5-coder:1.5b-base','phi-3-mini','llama3.2','nemotron-3-nano:4b','embeddinggemma') + $ollamaModels
    $pickIdx = -1
    $pickText = ''
    foreach ($sub in $preferSub) {
      if ([string]::IsNullOrWhiteSpace($sub)) { continue }
      for ($i = 0; $i -lt $comboRows.Count; $i++) {
        if ($comboRows[$i] -match '(?i)ollama' -and $comboRows[$i] -like "*$sub*") {
          $pickIdx = $i; $pickText = $comboRows[$i]; break
        }
      }
      if ($pickIdx -ge 0) { break }
    }
    if ($pickIdx -lt 0) {
      for ($i = 0; $i -lt $comboRows.Count; $i++) {
        if ($comboRows[$i] -match '(?i)ollama' -and $comboRows[$i] -notmatch 'connecting') {
          $pickIdx = $i; $pickText = $comboRows[$i]; break
        }
      }
    }
    if ($pickIdx -ge 0) {
      [void][CancelRecov010]::SendMessageW($combo, 0x014F, [IntPtr]::Zero, [IntPtr]::Zero)
      [CancelRecov010]::SelectComboIndex($sidebar, $combo, $pickIdx, 1206)
      [CancelRecov010]::SelectComboIndex($main, $combo, $pickIdx, 1206)
      $modelSelected = $pickText
      WLog "MODEL_SELECT_IDX=$pickIdx text=$pickText"
      Start-Sleep -Milliseconds 2000
    }
  }

  if (-not $modelSelected) {
    $disposition = 'FAIL_CLOSED_NO_MODEL'
    $gate04='FAIL'; $gate05='FAIL'; $gate06='FAIL'; $gate07='FAIL'; $gate08='FAIL'
    WLog $disposition
    Write-Receipt $disposition
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    exit 5
  }

  $promptA = 'Write a very long detailed essay of at least 2000 words about Windows kernel scheduling, memory management, and I/O completion ports. Include multiple sections.'
  [void][CancelRecov010]::SetEdit($inputEdit, $promptA)
  Start-Sleep -Milliseconds 300
  [CancelRecov010]::ClickChild($sidebar, $btnSend, 1204)
  WLog 'REQUEST_A_SUBMITTED'
  Start-Sleep -Milliseconds 500

  $armed = 0
  $armDeadline = (Get-Date).AddSeconds(30)
  $armTick = 0
  while ((Get-Date) -lt $armDeadline) {
    if ($proc.HasExited) {
      WLog ("CRASH_DURING_ARM exit={0}" -f $proc.ExitCode)
      break
    }
    $st = [CancelRecov010]::StatusBarText($main)
    $stopEn = [int][CancelRecov010]::IsWindowEnabled($btnStop)
    $outNow = [CancelRecov010]::Text($outputEdit)
    $armTick++
    if (($armTick % 5) -eq 1) {
      WLog "ARM_POLL stopEnabled=$stopEn status='$st' outLen=$($outNow.Length)"
    }
    if ($stopEn -eq 1 -or $st -match '(?i)warming|waiting|running|Ollama|already running') {
      $armed = 1
      WLog "REQUEST_A_ARMED stopEnabled=$stopEn status='$st'"
      break
    }
    Start-Sleep -Milliseconds 200
  }
  if ($armed -ne 1) {
    if ($proc.HasExited) { $disposition = 'FAIL_CLOSED_CRASH_ON_REQUEST_A' }
    else { $disposition = 'FAIL_CLOSED_REQUEST_A_NOT_ARMED' }
    $gate04='FAIL'; $gate05='FAIL'; $gate06='FAIL'; $gate07='FAIL'; $gate08='FAIL'
    WLog $disposition
    Write-Receipt $disposition
    if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
    exit 6
  }

  Start-Sleep -Milliseconds 1500

  [CancelRecov010]::ClickChild($sidebar, $btnStop, 1210)
  $stopAt = Get-Date
  WLog 'STOP_CLICKED'
  Start-Sleep -Milliseconds 300
  $stStop = [CancelRecov010]::StatusBarText($main)
  WLog "STATUS_AFTER_STOP=$stStop"
  if ($stStop -match '(?i)stop|cancel') { $stopSignalObserved = 1; $gate04 = 'PASS' }
  else {
    $stopEnAfter = [int][CancelRecov010]::IsWindowEnabled($btnStop)
    WLog "STOP_BTN_ENABLED_AFTER=$stopEnAfter"
    if ($stopEnAfter -eq 0) { $stopSignalObserved = 1; $gate04 = 'PASS' }
    else { $gate04 = 'FAIL' }
  }

  $waitMs = [Math]::Max(0, 5000 - [int]((Get-Date) - $stopAt).TotalMilliseconds)
  if ($waitMs -gt 0) { Start-Sleep -Milliseconds $waitMs }
  $elapsedStopMs = [int]((Get-Date) - $stopAt).TotalMilliseconds
  WLog "POST_STOP_WAIT_MS=$elapsedStopMs (cap 5000)"

  $stBeforeB = [CancelRecov010]::StatusBarText($main)
  WLog "STATUS_BEFORE_B=$stBeforeB"
  $outBeforeB = [CancelRecov010]::Text($outputEdit)
  $promptB = 'Reply with exactly one word: PONG_B'
  [void][CancelRecov010]::SetEdit($inputEdit, $promptB)
  Start-Sleep -Milliseconds 150
  [CancelRecov010]::ClickChild($sidebar, $btnSend, 1204)
  WLog 'REQUEST_B_SUBMITTED'

  $bDeadline = (Get-Date).AddSeconds(90)
  $statusTrailB = New-Object System.Collections.Generic.List[string]
  while ((Get-Date) -lt $bDeadline) {
    if ($proc.HasExited) {
      WLog "CRASH_DURING_B exit=$($proc.ExitCode)"
      break
    }
    $st = [CancelRecov010]::StatusBarText($main)
    $outNow = [CancelRecov010]::Text($outputEdit)
    if ($st -and ($statusTrailB.Count -eq 0 -or $statusTrailB[$statusTrailB.Count-1] -ne $st)) {
      $statusTrailB.Add($st)
      WLog "STATUS_B=$st"
    }
    if ($st -match '(?i)already running') {
      $busyRejected = 1
      $requestBAccepted = 0
      WLog 'REQUEST_B_REJECTED_ALREADY_RUNNING'
      break
    }
    if ($st -match '(?i)warming|waiting for response|response received|request finished') {
      $requestBAccepted = 1
    }
    if ($outNow.Length -gt $outBeforeB.Length + 3) {
      if ($outNow -match 'PONG_B' -or $outNow.Length -gt $outBeforeB.Length + 15) {
        $requestBAccepted = 1
        $requestBResponse = 1
        WLog ("OUTPUT_B_GREW before={0} after={1}" -f $outBeforeB.Length, $outNow.Length)
        break
      }
    }
    Start-Sleep -Milliseconds 400
  }
  $statusTrailB | Set-Content -LiteralPath (Join-Path $Logs 'status_trail_request_b.txt')
  [CancelRecov010]::Text($outputEdit) | Set-Content -LiteralPath (Join-Path $Logs 'output_after_request_b.txt')
  $stStop | Set-Content -LiteralPath (Join-Path $Logs 'status_after_stop.txt')

  if ($busyRejected -eq 1) {
    $gate06 = 'FAIL'; $gate07 = 'FAIL'; $gate05 = 'FAIL'; $gate08 = 'FAIL'
    $disposition = 'FAIL_REQUEST_B_ALREADY_RUNNING'
  } elseif ($requestBAccepted -eq 1) {
    $gate06 = 'PASS'; $gate07 = 'PASS'; $gate05 = 'PASS'
    if ($requestBResponse -eq 1) { $gate08 = 'PASS' } else { $gate08 = 'FAIL' }
    if ($gate04 -ne 'PASS') { $gate04 = 'FAIL' }
    if ($gate08 -eq 'PASS' -and $gate04 -eq 'PASS') { $disposition = 'PASS_GATES_04_08' }
    else { $disposition = 'PARTIAL_B_ADMITTED_RESPONSE_OR_SIGNAL_GAP' }
  } else {
    $gate06 = 'FAIL'; $gate07 = 'FAIL'; $gate05 = 'FAIL'; $gate08 = 'FAIL'
    if ($gate04 -ne 'PASS') { $gate04 = 'FAIL' }
    $disposition = 'FAIL_CLOSED_REQUEST_B_NOT_OBSERVED'
  }

  WLog "GATES 04=$gate04 05=$gate05 06=$gate06 07=$gate07 08=$gate08"
  WLog "BATCH1_10=$gate05 BATCH1_11=$gate07"
  WLog "DISPOSITION=$disposition"

  [void][CancelRecov010]::PostMessageW($main, [CancelRecov010]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
  Start-Sleep -Milliseconds 800
  if (-not $proc.HasExited) { Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue }
  Start-Sleep -Seconds 1

  Write-Receipt $disposition
  $afterSha = (Get-FileHash -LiteralPath $TipExe -Algorithm SHA256).Hash
  WLog "POST_SHA256=$afterSha"
  if ($disposition -eq 'PASS_GATES_04_08') { exit 0 } else { exit 1 }
}
catch {
  WLog ("EXCEPTION={0}" -f $_.Exception.Message)
  $disposition = 'FAIL_CLOSED_EXCEPTION'
  if ($gate04 -eq 'NOT_RUN') { $gate04='FAIL' }
  if ($gate05 -eq 'NOT_RUN') { $gate05='FAIL' }
  if ($gate06 -eq 'NOT_RUN') { $gate06='FAIL' }
  if ($gate07 -eq 'NOT_RUN') { $gate07='FAIL' }
  if ($gate08 -eq 'NOT_RUN') { $gate08='FAIL' }
  Write-Receipt $_.Exception.Message
  exit 3
}
