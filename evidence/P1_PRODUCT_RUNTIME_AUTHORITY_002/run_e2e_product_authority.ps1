# P1PRA_002 physical E2E - Load GGUF from G:\OllamaModels -> Build Send -> E2E.log
$ErrorActionPreference = 'Stop'
$env:RAWRXD_EVIDENCE_ROOT = 'f:\~dev\rawrxd\evidence'
$env:OLLAMA_MODELS = 'G:\OllamaModels'
$env:RAWRXD_MODELS_PATH = 'G:\OllamaModels\Phi-3-mini-4k-instruct-q8_0.gguf'
# Host fault: amdvlk64.dll BEX64 / ntdll AV during model load - disable Vulkan ICD.
$env:VK_ICD_FILENAMES = 'C:\__no_vulkan_icd__.json'
$env:VK_DRIVER_FILES = 'C:\__no_vulkan_icd__.json'
$env:DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1 = '1'
$env:RAWRXD_SKIP_STREAMER_POSTLOAD = '1'
$env:RAWRXD_FORCE_CPU_INFERENCE = '1'
$env:RAWRXD_BRIDGE_CPU_ONLY = '1'
$env:RAWRXD_SKIP_DEFERRED_MODEL_LOAD = '1'
$env:RAWRXD_INFERENCE_CTX = '512'
# Full P1PRA cert requires MASM UTC path — do not inherit isolation skip from shell.
Remove-Item Env:RAWRXD_SKIP_UTC_MASM -ErrorAction SilentlyContinue
$exe = if ($env:RAWRXD_E2E_EXE) { $env:RAWRXD_E2E_EXE } else { 'F:\~dev\rawrxd\build_p1pra_win32ide\bin\RawrXD-Win32IDE.exe' }
$e2e = 'f:\~dev\rawrxd\evidence\P1_PRODUCT_RUNTIME_AUTHORITY_002\E2E.log'
$run = 'f:\~dev\rawrxd\evidence\P1_PRODUCT_RUNTIME_AUTHORITY_002\RUN.log'
$witness = 'f:\~dev\rawrxd\evidence\P1_PRODUCT_RUNTIME_AUTHORITY_002\WITNESS.log'
$model = $env:RAWRXD_MODELS_PATH

function Get-FreshLogLines {
  param(
    [Parameter(Mandatory)][string]$Path,
    [int]$StartLines = 0
  )
  if (-not (Test-Path -LiteralPath $Path)) { return @() }
  $all = @(Get-Content -LiteralPath $Path -ErrorAction SilentlyContinue)
  if ($StartLines -ge $all.Count) { return @() }
  return @($all[$StartLines..($all.Count - 1)])
}

function Get-FreshWitnessBlob {
  param([int]$StartLines)
  return ((Get-FreshLogLines -Path $witness -StartLines $StartLines) -join "`n")
}

function Test-FreshWitnessMatch {
  param([int]$StartLines, [string]$Pattern)
  $fresh = Get-FreshLogLines -Path $witness -StartLines $StartLines
  return [bool]($fresh | Where-Object { $_ -match $Pattern })
}

function Test-ValidAuthorityFinalize {
  param(
    [string]$RunPath,
    [int]$RunStartLines,
    [string]$WitnessPath,
    [int]$WitnessStartLines,
    [string]$E2ePath
  )
  $freshRun = Get-FreshLogLines -Path $RunPath -StartLines $RunStartLines
  $freshWitness = Get-FreshLogLines -Path $WitnessPath -StartLines $WitnessStartLines
  $runBlob = ($freshRun -join "`n")
  $witnessBlob = ($freshWitness -join "`n")

  if ($runBlob -match '--- phase=startup' -and $runBlob -notmatch 'P1PRA_USER_PROMPT_COUNT=[1-9]\d*') {
    Write-Host 'VALID_FINALIZE=FAIL reason=startup_only_no_user_prompt'
    return $false
  }

  $finalizeOne = ($runBlob -match '(?m)^P1PRA_FINALIZE=1$') -or ($runBlob -match 'P1PRA_FINALIZE=1\b')
  $requestId = 0
  if ($runBlob -match 'P1PRA_REQUEST_ID=(\d+)') {
    $requestId = [int]$Matches[1]
  }
  $promptCount = 0
  if ($runBlob -match 'P1PRA_USER_PROMPT_COUNT=(\d+)') {
    $promptCount = [int]$Matches[1]
  }
  $authorityTag = ($witnessBlob -match 'AUTHORITY_FINAL_TAG=(?!0{16}\b)') -or
                  ($runBlob -match 'AUTHORITY_FINAL_TAG=(?!0{16}\b)')
  $replayMatch = ($witnessBlob -match 'REPLAY_MATCH=1\b') -or ($runBlob -match 'REPLAY_MATCH=1\b')
  $uiEmit = Test-FreshWitnessMatch -StartLines $WitnessStartLines -Pattern 'P1PRA_HOOK=UI_EMIT adv=1'

  $ok = $finalizeOne -and ($requestId -gt 0) -and ($promptCount -gt 0) -and $authorityTag -and $replayMatch -and $uiEmit
  if ($ok) {
    Write-Host "VALID_FINALIZE=PASS request_id=$requestId prompt_count=$promptCount"
  } else {
    Write-Host "VALID_FINALIZE=FAIL finalize=$finalizeOne request_id=$requestId prompt_count=$promptCount authority_tag=$authorityTag replay_match=$replayMatch ui_emit=$uiEmit"
  }
  return $ok
}

if (-not (Test-Path $exe)) { throw "EXE missing: $exe" }
if (-not (Test-Path $model)) { throw "MODEL missing: $model" }

$archiveDir = Join-Path (Split-Path $e2e) 'reconclusion\archive'
New-Item -ItemType Directory -Force -Path $archiveDir | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
foreach ($src in @($e2e, $run, $witness)) {
  if (Test-Path $src) {
    $leaf = [System.IO.Path]::GetFileName($src)
    Copy-Item $src (Join-Path $archiveDir "${stamp}_${leaf}") -Force
  }
}

Remove-Item $e2e -ErrorAction SilentlyContinue
Remove-Item $run -ErrorAction SilentlyContinue

$WitnessStartLines = if (Test-Path -LiteralPath $witness) {
  @(Get-Content -LiteralPath $witness -ErrorAction SilentlyContinue).Count
} else { 0 }
$RunStartLines = 0
Write-Host "witness_line_baseline=$WitnessStartLines run_line_baseline=$RunStartLines"

Add-Type @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class P1E2E {
  public delegate bool EnumProc(IntPtr hWnd, IntPtr lParam);
  [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc lpEnumFunc, IntPtr lParam);
  [DllImport("user32.dll")] public static extern bool EnumChildWindows(IntPtr hWndParent, EnumProc lpEnumFunc, IntPtr lParam);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern int GetWindowText(IntPtr hWnd, StringBuilder lpString, int nMaxCount);
  [DllImport("user32.dll")] public static extern IntPtr GetParent(IntPtr hWnd);
  [DllImport("user32.dll")] public static extern bool PostMessage(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
  [DllImport("user32.dll")] public static extern int GetDlgCtrlID(IntPtr hWnd);
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr hWnd, out uint lpdwProcessId);
  [DllImport("user32.dll", EntryPoint="GetWindowLongPtrW")]
  public static extern IntPtr GetWindowLongPtr(IntPtr hWnd, int nIndex);
  [DllImport("user32.dll")] public static extern bool IsWindow(IntPtr hWnd);
  public const int GWLP_USERDATA = -21;
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern IntPtr GetDlgItem(IntPtr hDlg, int nIDDlgItem);
  [DllImport("user32.dll", CharSet=CharSet.Unicode)] public static extern bool SetWindowText(IntPtr hWnd, string lpString);
  [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageW")]
  public static extern IntPtr SendMessageText(IntPtr hWnd, uint Msg, IntPtr wParam, string lParam);
  [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageW")]
  public static extern IntPtr SendMessagePtr(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);
  [DllImport("user32.dll", CharSet=CharSet.Unicode, EntryPoint="SendMessageW")]
  public static extern IntPtr SendMessageStr(IntPtr hWnd, uint Msg, IntPtr wParam, StringBuilder lParam);
  public const uint WM_SETTEXT = 0x000C;
  public const uint WM_CLOSE = 0x0010;
  public const uint WM_COMMAND = 0x0111;
  public const uint WM_APP = 0x8000;
  public const uint WM_APP_P1PRA_E2E_SEND = WM_APP + 209;
  public const uint CB_SETCURSEL = 0x014E;
  public const uint LB_SETCURSEL = 0x0186;
  public const uint LB_GETCOUNT = 0x018B;
  public const uint LB_GETTEXT = 0x0189;
  public static string ListBoxGetText(IntPtr list, int index) {
    var sb = new StringBuilder(2048);
    SendMessageStr(list, LB_GETTEXT, (IntPtr)index, sb);
    return sb.ToString();
  }
  public static IntPtr FindByCtrlId(IntPtr root, int id) {
    IntPtr found = IntPtr.Zero;
    EnumChildWindows(root, (h, p) => {
      if (GetDlgCtrlID(h) == id) { found = h; return false; }
      return true;
    }, IntPtr.Zero);
    if (found != IntPtr.Zero) return found;
    EnumChildWindows(root, (h, p) => {
      var sub = FindByCtrlIdDeep(h, id);
      if (sub != IntPtr.Zero) { found = sub; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  static IntPtr FindByCtrlIdDeep(IntPtr root, int id) {
    IntPtr found = IntPtr.Zero;
    if (GetDlgCtrlID(root) == id) return root;
    EnumChildWindows(root, (h, p) => {
      if (GetDlgCtrlID(h) == id) { found = h; return false; }
      var nested = FindByCtrlIdDeep(h, id);
      if (nested != IntPtr.Zero) { found = nested; return false; }
      return true;
    }, IntPtr.Zero);
    return found;
  }
  public static IntPtr FindMainForPid(uint pid) {
    IntPtr found = IntPtr.Zero;
    EnumWindows((h, p) => {
      uint wp = 0;
      GetWindowThreadProcessId(h, out wp);
      if (wp != pid) return true;
      var sb = new StringBuilder(512);
      GetWindowText(h, sb, sb.Capacity);
      var t = sb.ToString();
      if (t.IndexOf("ScreenPilot", StringComparison.OrdinalIgnoreCase) >= 0 ||
          t.IndexOf("RawrXD", StringComparison.OrdinalIgnoreCase) >= 0) {
        found = h;
        return false;
      }
      return true;
    }, IntPtr.Zero);
    return found;
  }
}
'@

Write-Host "MODEL=$model"
Write-Host "EXE=$exe"
$leaveRunning = ($env:RAWRXD_E2E_SHUTDOWN -ne '1')
$attachExisting = ($env:RAWRXD_E2E_ATTACH -eq '1')
$forceLoad = ($env:RAWRXD_E2E_FORCE_LOAD -eq '1')
$skipLoad = ($env:RAWRXD_E2E_SKIP_LOAD -eq '1')
$p = $null
$main = [IntPtr]::Zero

function Get-ProcessForMainHwnd([IntPtr]$hwnd) {
  if ($hwnd -eq [IntPtr]::Zero) { return $null }
  $pidOut = [uint32]0
  [void][P1E2E]::GetWindowThreadProcessId($hwnd, [ref]$pidOut)
  if ($pidOut -eq 0) { return $null }
  return Get-Process -Id $pidOut -ErrorAction SilentlyContinue
}

function Test-IdeProcessAlive([ref]$MainHwnd, [ref]$Proc) {
  $procNow = Get-ProcessForMainHwnd $MainHwnd.Value
  if ($procNow) {
    $Proc.Value = $procNow
    return $true
  }
  $pidHint = 0
  if ($Proc.Value) { $pidHint = $Proc.Value.Id }
  $mainNow = [IntPtr]::Zero
  if ($pidHint -gt 0) {
    $mainNow = [P1E2E]::FindMainForPid([uint32]$pidHint)
  }
  if ($mainNow -eq [IntPtr]::Zero) {
    $script:mainNow = [IntPtr]::Zero
    [P1E2E]::EnumWindows([P1E2E+EnumProc]{
      param($h, $lp)
      $sb = New-Object System.Text.StringBuilder 512
      [void][P1E2E]::GetWindowText($h, $sb, $sb.Capacity)
      $t = $sb.ToString()
      if ($t -like '*ScreenPilot*' -or $t -like '*RawrXD*') { $script:mainNow = $h; return $false }
      return $true
    }, [IntPtr]::Zero) | Out-Null
    $mainNow = $script:mainNow
  }
  if ($mainNow -ne [IntPtr]::Zero) {
    $MainHwnd.Value = $mainNow
    $procNow = Get-ProcessForMainHwnd $mainNow
    if ($procNow) {
      $Proc.Value = $procNow
      return $true
    }
  }
  return $false
}

function Test-ModelStatusReady([IntPtr]$MainHwnd) {
  $status = [P1E2E]::FindByCtrlId($MainHwnd, 12535)
  if ($status -eq [IntPtr]::Zero) { return $false }
  $sb = New-Object System.Text.StringBuilder 256
  [void][P1E2E]::GetWindowText($status, $sb, $sb.Capacity)
  $st = $sb.ToString()
  return ($st -match 'ready|loaded|Deep2' -and $st -notmatch 'Loading|failed|No model')
}

function Test-ModelLoadSatisfied([IntPtr]$MainHwnd, [string]$WitnessPath, [int]$WitnessLineAfter = 0) {
  $status = [P1E2E]::FindByCtrlId($MainHwnd, 12535)
  if ($status -ne [IntPtr]::Zero) {
    $sb = New-Object System.Text.StringBuilder 256
    [void][P1E2E]::GetWindowText($status, $sb, $sb.Capacity)
    $st = $sb.ToString()
    if ($st -match 'ready|loaded|Deep2' -and $st -notmatch 'Loading|failed|No model') {
      $freshWitness = Get-FreshLogLines -Path $WitnessPath -StartLines $WitnessLineAfter
      $freshWorkerOk = [bool]($freshWitness | Where-Object { $_ -match 'P1PRA_LOAD=worker_ok' })
      $freshModelReady = [bool]($freshWitness | Where-Object { $_ -match 'P1PRA_LOAD=model_ready' })
      if ($freshWorkerOk -and $freshModelReady) {
        return @{ ok = $true; reason = "status=$st;witness=fresh_worker_ok+model_ready" }
      }
      return @{ ok = $false; reason = "status_ready_but_fresh_worker_ok=$freshWorkerOk fresh_model_ready=$freshModelReady" }
    }
  }
  if (Test-Path -LiteralPath $WitnessPath) {
    $freshWitness = Get-FreshLogLines -Path $WitnessPath -StartLines $WitnessLineAfter
    $blob = ($freshWitness -join "`n")
    if ($blob -match 'P1PRA_LOAD=worker_fail' -or $blob -match 'P1PRA_LOAD=gguf_load_fail' -or $blob -match 'P1PRA_LOAD=after_load_fail') {
      return @{ ok = $false; reason = 'witness=fresh_worker_fail' }
    }
    $freshWorkerOk = [bool]($freshWitness | Where-Object { $_ -match 'P1PRA_LOAD=worker_ok' })
    $freshModelReady = [bool]($freshWitness | Where-Object { $_ -match 'P1PRA_LOAD=model_ready' })
    if ($freshWorkerOk -and $freshModelReady) {
      return @{ ok = $true; reason = 'witness=fresh_worker_ok+model_ready' }
    }
    if ($freshWorkerOk -and -not $freshModelReady) {
      return @{ ok = $false; reason = 'witness=fresh_worker_ok_without_model_ready' }
    }
    $lastLoad = ($freshWitness | Select-String 'P1PRA_LOAD=' | Select-Object -Last 1).Line
    if ($lastLoad) {
      return @{ ok = $false; reason = "witness=fresh_incomplete last=$lastLoad" }
    }
  }
  return @{ ok = $false; reason = 'not_ready' }
}

if ($attachExisting) {
  Write-Host 'E2E attach=existing (RAWRXD_E2E_ATTACH=1)'
  Write-Host 'attach_note=harness env vars apply only to spawned IDE; running IDE keeps its own env'
  for ($i = 0; $i -lt 120 -and $main -eq [IntPtr]::Zero; $i++) {
    [P1E2E]::EnumWindows([P1E2E+EnumProc]{
      param($h, $lp)
      $sb = New-Object System.Text.StringBuilder 512
      [void][P1E2E]::GetWindowText($h, $sb, $sb.Capacity)
      $t = $sb.ToString()
      if ($t -like '*ScreenPilot*' -or $t -like '*RawrXD*') { $script:main = $h; return $false }
      return $true
    }, [IntPtr]::Zero) | Out-Null
    if ($main -eq [IntPtr]::Zero) { Start-Sleep -Milliseconds 500 }
  }
  if ($main -eq [IntPtr]::Zero) { throw 'Attach mode: no ScreenPilot/RawrXD window found' }
  $p = Get-ProcessForMainHwnd $main
  if (-not $p) { throw 'Attach mode: could not resolve process for main window' }
  if ($p.ProcessName -notlike 'RawrXD*') {
    throw "Attach mode: HWND pid=$($p.Id) is $($p.ProcessName), expected RawrXD-Win32IDE"
  }
  Write-Host "attached pid=$($p.Id) main=$main exe=$($p.Path)"
} else {
  $p = Start-Process -FilePath $exe -PassThru
  for ($i = 0; $i -lt 180 -and $main -eq [IntPtr]::Zero; $i++) {
    Start-Sleep -Milliseconds 500
    [P1E2E]::EnumWindows([P1E2E+EnumProc]{
      param($h, $lp)
      $sb = New-Object System.Text.StringBuilder 512
      [void][P1E2E]::GetWindowText($h, $sb, $sb.Capacity)
      $t = $sb.ToString()
      if ($t -like '*ScreenPilot*' -or $t -like '*RawrXD*') { $script:main = $h; return $false }
      return $true
    }, [IntPtr]::Zero) | Out-Null
  }
  if ($main -eq [IntPtr]::Zero) {
    if (-not $leaveRunning) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
    throw 'Main window not found'
  }
}
Write-Host "main=$main"

$composer = [IntPtr]::Zero
$sendBtn = [IntPtr]::Zero
$modeCombo = [IntPtr]::Zero
$localList = [IntPtr]::Zero
$loadBtn = [IntPtr]::Zero
for ($i = 0; $i -lt 240; $i++) {
  $composer = [P1E2E]::FindByCtrlId($main, 12501)
  $sendBtn = [P1E2E]::FindByCtrlId($main, 12502)
  $modeCombo = [P1E2E]::FindByCtrlId($main, 12505)
  $localList = [P1E2E]::FindByCtrlId($main, 12532)
  $loadBtn = [P1E2E]::FindByCtrlId($main, 12533)
  if ($composer -ne [IntPtr]::Zero -and $sendBtn -ne [IntPtr]::Zero -and $localList -ne [IntPtr]::Zero) { break }
  Start-Sleep -Milliseconds 500
}
Write-Host "composer=$composer send=$sendBtn mode=$modeCombo list=$localList load=$loadBtn"
if ($composer -eq [IntPtr]::Zero -or $sendBtn -eq [IntPtr]::Zero) {
  if (-not $leaveRunning -and -not $attachExisting) {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
  }
  throw 'Command-home controls missing'
}

if ($modeCombo -ne [IntPtr]::Zero) {
  [void][P1E2E]::SendMessagePtr($modeCombo, [P1E2E]::CB_SETCURSEL, [IntPtr]1, [IntPtr]::Zero)
  Write-Host 'mode=Build'
}

if ($localList -ne [IntPtr]::Zero -and $loadBtn -ne [IntPtr]::Zero) {
  $statusReady = Test-ModelStatusReady $main
  if ($skipLoad -or ($attachExisting -and $statusReady -and -not $forceLoad)) {
    Write-Host "load_skip=1 reason=status_ready attach=$attachExisting force=$forceLoad"
  } else {
  $count = [P1E2E]::SendMessagePtr($localList, [P1E2E]::LB_GETCOUNT, [IntPtr]::Zero, [IntPtr]::Zero).ToInt32()
  Write-Host "inventory_count=$count"
  $sel = -1
  $pickDeadline = (Get-Date).AddSeconds(60)
  while ((Get-Date) -lt $pickDeadline -and $sel -lt 0) {
    $count = [P1E2E]::SendMessagePtr($localList, [P1E2E]::LB_GETCOUNT, [IntPtr]::Zero, [IntPtr]::Zero).ToInt32()
    for ($i = 0; $i -lt $count; $i++) {
      $text = [P1E2E]::ListBoxGetText($localList, $i)
      if ($text -match 'Phi-3-mini') {
        $sel = $i
        Write-Host "select[$i]=$text"
        break
      }
    }
    if ($sel -lt 0) { Start-Sleep -Milliseconds 500 }
  }
  if ($sel -lt 0) {
    for ($i = 0; $i -lt $count; $i++) {
      $text = [P1E2E]::ListBoxGetText($localList, $i)
      if ($text -match '\.gguf' -and $text -notmatch 'dummy') {
        $sel = $i
        Write-Host "fallback[$i]=$text"
        break
      }
    }
  }
  if ($sel -lt 0) {
    throw "Phi-3-mini not found in local inventory (count=$count) — refusing index=0 fallback"
  }
  [void][P1E2E]::SendMessagePtr($localList, [P1E2E]::LB_SETCURSEL, [IntPtr]$sel, [IntPtr]::Zero)
  $picked = [P1E2E]::ListBoxGetText($localList, $sel)
  Write-Host "load_target[$sel]=$picked"
  $cmdHost = [P1E2E]::GetParent($loadBtn)
  $witnessLineBefore = 0
  if (Test-Path $witness) { $witnessLineBefore = @(Get-Content $witness -ErrorAction SilentlyContinue).Count }
  # PostMessage: Load can take minutes on UI thread; SendMessage would block automation and hide crashes.
  $posted = [P1E2E]::PostMessage($cmdHost, [P1E2E]::WM_COMMAND, [IntPtr]12533, $loadBtn)
  Write-Host "posted Load selected index=$sel PostMessage=$posted witness_line_before=$witnessLineBefore - polling up to 600s for model/process"
  $loadDeadline = (Get-Date).AddSeconds(600)
  $loadSatisfied = $false
  while ((Get-Date) -lt $loadDeadline) {
    if (-not (Test-IdeProcessAlive ([ref]$main) ([ref]$p))) {
      $exitHint = ''
      if ($p -and $p.HasExited) {
        try { $exitHint = $p.ExitCode } catch { $exitHint = 'unknown' }
      }
      throw "IDE process exited during model load (last_pid=$($p.Id) exit=$exitHint)"
    }
    $aliveMain = [P1E2E]::FindMainForPid([uint32]$p.Id)
    if ($aliveMain -ne [IntPtr]::Zero) { $main = $aliveMain }
    $satisfied = Test-ModelLoadSatisfied -MainHwnd $main -WitnessPath $witness -WitnessLineAfter $witnessLineBefore
    if ($satisfied.ok) {
      Write-Host "model_load=$($satisfied.reason)"
      $loadSatisfied = $true
      break
    }
    if ($satisfied.reason -eq 'witness=fresh_worker_fail') {
      throw 'Model load failed (witness=fresh_worker_fail in current run)'
    }
    $status = [P1E2E]::FindByCtrlId($main, 12535)
    if ($status -ne [IntPtr]::Zero) {
      $sb = New-Object System.Text.StringBuilder 256
      [void][P1E2E]::GetWindowText($status, $sb, $sb.Capacity)
      $st = $sb.ToString()
      if ($st -match 'failed|No model') { Write-Host "model_status_warn=$st" }
    }
    if (Test-Path $witness) {
      $freshTail = @(Get-FreshLogLines -Path $witness -StartLines $witnessLineBefore | Select-Object -Last 6)
      if ($freshTail -match 'P1PRA_LOAD_ERR=') { Write-Host "witness_load_err=$freshTail" }
    }
    Start-Sleep -Seconds 2
  }
  if (-not $loadSatisfied) {
    $lastLoad = ''
    if (Test-Path $witness) {
      $freshLoad = Get-FreshLogLines -Path $witness -StartLines $witnessLineBefore
      $lastLoad = ($freshLoad | Select-String 'P1PRA_LOAD=' | Select-Object -Last 1).Line
      $freshWorkerOk = Test-FreshWitnessMatch -StartLines $witnessLineBefore -Pattern 'P1PRA_LOAD=worker_ok'
      $freshModelReady = Test-FreshWitnessMatch -StartLines $witnessLineBefore -Pattern 'P1PRA_LOAD=model_ready'
      Write-Host "CURRENT_FRESH_worker_ok=$(if ($freshWorkerOk) { 'PRESENT' } else { 'ABSENT' })"
      Write-Host "CURRENT_FRESH_model_ready=$(if ($freshModelReady) { 'PRESENT' } else { 'ABSENT' })"
    }
    throw "Model load not satisfied within 600s (fresh_last_witness=$lastLoad)"
  }
  if (-not (Test-IdeProcessAlive ([ref]$main) ([ref]$p))) {
    $exitHint = ''
    if ($p -and $p.HasExited) {
      try { $exitHint = $p.ExitCode } catch { $exitHint = 'unknown' }
    }
    throw "IDE process exited during model load (last_pid=$($p.Id) exit=$exitHint)"
  }
  }
}

# Re-acquire main HWND + controls after load (pre-load handles go stale; process may recreate shell).
if (Test-IdeProcessAlive ([ref]$main) ([ref]$p)) {
  $mainNew = [IntPtr]::Zero
  for ($i = 0; $i -lt 120 -and $mainNew -eq [IntPtr]::Zero; $i++) {
    $mainNew = [P1E2E]::FindMainForPid([uint32]$p.Id)
    if ($mainNew -ne [IntPtr]::Zero) { break }
    Start-Sleep -Milliseconds 500
  }
  if ($mainNew -ne [IntPtr]::Zero) {
    if ($mainNew -ne $main) { Write-Host "main_reacquired=$mainNew (was $main)" }
    $main = $mainNew
  } else {
    Write-Host "main_reacquire_miss pid=$($p.Id) - retrying with cached main=$main"
  }
} else {
  throw "IDE process exited during model load (pid=$($p.Id))"
}

for ($i = 0; $i -lt 60; $i++) {
  $composer = [P1E2E]::FindByCtrlId($main, 12501)
  $sendBtn = [P1E2E]::FindByCtrlId($main, 12502)
  if ($composer -ne [IntPtr]::Zero -and $sendBtn -ne [IntPtr]::Zero) { break }
  Start-Sleep -Milliseconds 500
}
if ($composer -eq [IntPtr]::Zero -or $sendBtn -eq [IntPtr]::Zero) {
  if (-not $leaveRunning -and -not $attachExisting) {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
  }
  throw "Command-home controls missing after load (composer=$composer send=$sendBtn)"
}

function Invoke-CommandSend {
  param([IntPtr]$MainHwnd, [System.Diagnostics.Process]$Proc)
  if ($MainHwnd -eq [IntPtr]::Zero) { return $false }
  if (-not [P1E2E]::IsWindow($MainHwnd)) { return $false }
  if ($Proc.HasExited) { return $false }
  Start-Sleep -Milliseconds 500
  $pidOut = [uint32]0
  $tid = [P1E2E]::GetWindowThreadProcessId($MainHwnd, [ref]$pidOut)
  $userdata = [P1E2E]::GetWindowLongPtr($MainHwnd, [P1E2E]::GWLP_USERDATA)
  Write-Host "P1PRA_E2E_TARGET hwnd=$MainHwnd pid=$pidOut tid=$tid userdata=$userdata"
  if ($userdata -eq [IntPtr]::Zero) {
    Write-Host 'P1PRA_E2E_POSTSTATE skip=userdata_zero'
    return $false
  }
  $posted = [P1E2E]::PostMessage($MainHwnd, [P1E2E]::WM_APP_P1PRA_E2E_SEND, [IntPtr]::Zero, [IntPtr]::Zero)
  $isWin = [P1E2E]::IsWindow($MainHwnd)
  $procAlive = -not $Proc.HasExited
  Write-Host "P1PRA_E2E_POSTSTATE posted=$posted iswindow=$isWin proc_alive=$procAlive proc_exit=$($Proc.ExitCode)"
  return $posted
}

Start-Sleep -Seconds 1
Write-Host 'send_phase_begin'
$userPromptSeen = $false
$sendPosted = $false
$sendResultAuthoritative = $false
$userPromptDeadline = (Get-Date).AddSeconds(120)
while ((Get-Date) -lt $userPromptDeadline) {
  if (-not (Test-IdeProcessAlive ([ref]$main) ([ref]$p))) {
    throw "IDE exited before Send (last_pid=$($p.Id))"
  }
  $aliveMain = [P1E2E]::FindMainForPid([uint32]$p.Id)
  if ($aliveMain -ne [IntPtr]::Zero) { $main = $aliveMain }
  if (-not $sendPosted) {
    $sendPosted = Invoke-CommandSend -MainHwnd $main -Proc $p
    if ($sendPosted) { Write-Host 'P1PRA_E2E_SEND posted_once=1' }
  }
  $freshRun = Get-FreshLogLines -Path $run -StartLines $RunStartLines
  $freshRunBlob = ($freshRun -join "`n")
  if ($freshRunBlob -match 'phase=user_prompt' -and $freshRunBlob -match 'P1PRA_USER_PROMPT_COUNT=[1-9]\d*') {
    Write-Host 'RUN.log user_prompt=PASS (fresh-run scoped)'
    $userPromptSeen = $true
    $sendResultAuthoritative = $true
    break
  }
  $freshSendAccepted = Test-FreshWitnessMatch -StartLines $WitnessStartLines -Pattern 'P1PRA_SEND=accepted'
  if ($freshSendAccepted) {
    Write-Host 'WITNESS P1PRA_SEND=accepted (fresh-run scoped)'
    $userPromptSeen = $true
    $sendResultAuthoritative = $true
    break
  }
  Start-Sleep -Seconds 2
}
if (-not $userPromptSeen) {
  Write-Host 'RUN.log user_prompt=FAIL (Send boundary not reached in fresh-run scope)'
  Write-Host 'SEND_RESULT=NOT_AUTHORITATIVE'
} elseif (-not $sendResultAuthoritative) {
  Write-Host 'SEND_RESULT=NOT_AUTHORITATIVE'
} else {
  Write-Host 'SEND_RESULT=AUTHORITATIVE'
}

Write-Host 'waiting for E2E.log'
$deadline = (Get-Date).AddMinutes(10)
while ((Get-Date) -lt $deadline) {
  if (Test-Path $e2e) {
    $tail = Get-Content $e2e -Raw -ErrorAction SilentlyContinue
    if ($tail -match 'FINALIZE=') { break }
  }
  Start-Sleep -Seconds 5
}

if ($leaveRunning) {
  Write-Host 'E2E leave_running=1 (IDE stays open; set RAWRXD_E2E_SHUTDOWN=1 to close)'
} else {
  [void][P1E2E]::PostMessage($main, [P1E2E]::WM_CLOSE, [IntPtr]::Zero, [IntPtr]::Zero)
  Wait-Process -Id $p.Id -Timeout 60 -ErrorAction SilentlyContinue
  if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
}

Write-Host '===== E2E.log ====='
if (Test-Path $e2e) { Get-Content $e2e } else { Write-Host 'E2E.log MISSING' }
Write-Host '===== WITNESS.log fresh tail (this run) ====='
$freshWitnessTail = @(Get-FreshLogLines -Path $witness -StartLines $WitnessStartLines | Select-Object -Last 30)
if ($freshWitnessTail.Count -gt 0) { $freshWitnessTail } else { Write-Host 'WITNESS fresh tail EMPTY' }
Write-Host '===== RUN.log fresh tail (this run) ====='
$freshRunTail = @(Get-FreshLogLines -Path $run -StartLines $RunStartLines | Select-Object -Last 50)
if ($freshRunTail.Count -gt 0) { $freshRunTail } else { Write-Host 'RUN.log fresh tail EMPTY' }

$freshHook = Test-FreshWitnessMatch -StartLines $WitnessStartLines -Pattern 'P1PRA_HOOK='
$freshAuthorityTag = Test-FreshWitnessMatch -StartLines $WitnessStartLines -Pattern 'AUTHORITY_FINAL_TAG='
$freshReplay = Test-FreshWitnessMatch -StartLines $WitnessStartLines -Pattern 'REPLAY_MATCH='
Write-Host "FRESH_WITNESS_HOOK=$(if ($freshHook) { 'PRESENT' } else { 'ABSENT' })"
Write-Host "FRESH_WITNESS_AUTHORITY_FINAL_TAG=$(if ($freshAuthorityTag) { 'PRESENT' } else { 'ABSENT' })"
Write-Host "FRESH_WITNESS_REPLAY_MATCH=$(if ($freshReplay) { 'PRESENT' } else { 'ABSENT' })"

$validFinalize = Test-ValidAuthorityFinalize -RunPath $run -RunStartLines $RunStartLines -WitnessPath $witness -WitnessStartLines $WitnessStartLines -E2ePath $e2e

if (-not $userPromptSeen) { exit 1 }
if (-not $sendResultAuthoritative) { exit 1 }
if (-not (Test-Path $e2e)) { exit 1 }
$e2eBody = Get-Content $e2e -Raw -ErrorAction SilentlyContinue
if ($e2eBody -notmatch 'FINALIZE=0') { exit 1 }
if ($sendResultAuthoritative -and -not $validFinalize) { exit 1 }
