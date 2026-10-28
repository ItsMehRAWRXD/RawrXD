# WIN32IDE_UI_COMPLETION_PHASE7_001 - tip 748B HWND UI exercise
# PROMOTE=0 TIP_CLIMB=HOLD GhostText ABSORB=NOT_AUTHORIZED NO_INVENT_PASS
$ErrorActionPreference = "Continue"
$OutDir = "G:\~dev\rawrxd\evidence\WIN32IDE_UI_COMPLETION_PHASE7_001"
$TipExe = "G:\~dev\rawrxd\evidence\TIP_FREEZE_001\bin\RawrXD-Win32IDE.exe"
$ExpectSha = "748B210A8F17C6C47685BE1E2718CB0113C070E47881AD3A76B2EBB013934145"
$WitnessB421 = "B4212E46598F6490241A531C88C8D9A8DA37532B8C940A2C38BB35226C5D869F"
$ClassName = "RawrXD_IDE_MainWindow"
$WM_COMMAND = 0x0111
$ID_CHAT = 3007
$ID_AGENT_PANEL = 7057
$ID_SETTINGS = 5016
$ID_SETTINGS_T1 = 12040
$ID_GITDIFF = 11700

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
New-Item -ItemType Directory -Force -Path (Join-Path $OutDir "logs") | Out-Null
$Log = Join-Path $OutDir "RUNLOG.txt"
$Stdout = Join-Path $OutDir "logs\gui_stdout.txt"
$Stderr = Join-Path $OutDir "logs\gui_stderr.txt"
$ChildDump = Join-Path $OutDir "logs\child_hwnd_dump.txt"
$AgentProofOut = Join-Path $OutDir "logs\agent_gui_proof_stdout.txt"
$AgentProofErr = Join-Path $OutDir "logs\agent_gui_proof_stderr.txt"
"" | Set-Content -Path $Log

function WLog([string]$m) {
  $ts = Get-Date -Format "yyyy-MM-ddTHH:mm:ssK"
  $line = "[$ts] $m"
  Add-Content -Path $Log -Value $line
  Write-Host $line
}

$csPath = Join-Path $OutDir "TipUiPhase7.cs"
$csText = [IO.File]::ReadAllText($csPath)
try { Add-Type -TypeDefinition $csText -ErrorAction Stop } catch {
  if ($_.Exception.Message -notmatch "already exists") { throw }
}

WLog "START WIN32IDE_UI_COMPLETION_PHASE7_001"
WLog "PROMOTE=0 ABSORB=NOT_AUTHORIZED WITNESS_B421=$WitnessB421"

if (-not (Test-Path $TipExe)) { WLog "FAIL_CLOSED tip missing"; exit 2 }
$sha = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
Set-Content (Join-Path $OutDir "sha.txt") "TIP_SHA=$sha"
WLog "TIP_SHA=$sha"
if ($sha -ne $ExpectSha) {
  WLog "FAIL_CLOSED SHA_MISMATCH"
  exit 3
}

Get-Process -Name "RawrXD-Win32IDE" -ErrorAction SilentlyContinue | ForEach-Object {
  WLog "KILL_PRIOR pid=$($_.Id)"
  Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
}
Start-Sleep -Seconds 2

WLog "LAUNCH headless agent-gui-proof"
Remove-Item $AgentProofOut,$AgentProofErr -ErrorAction SilentlyContinue
$proof = Start-Process -FilePath $TipExe -ArgumentList @("--headless","--agent-gui-proof") `
  -WorkingDirectory (Split-Path $TipExe) `
  -RedirectStandardOutput $AgentProofOut -RedirectStandardError $AgentProofErr `
  -PassThru -WindowStyle Hidden
$waited = $proof.WaitForExit(60000)
if (-not $waited) {
  WLog "agent-gui-proof TIMEOUT"
  Stop-Process -Id $proof.Id -Force -ErrorAction SilentlyContinue
  $agentExit = -1
} else {
  $agentExit = $proof.ExitCode
}
WLog "AGENT_GUI_PROOF_EXIT=$agentExit"
$agentOut = ""
if (Test-Path $AgentProofOut) { $agentOut = [IO.File]::ReadAllText($AgentProofOut) }
$agentErr = ""
if (Test-Path $AgentProofErr) { $agentErr = [IO.File]::ReadAllText($AgentProofErr) }
$hasProofPass = $agentOut.Contains("AGENT_GUI_PROOF files=1 review=1")
$hasProofFail = $agentOut.Contains("AGENT_GUI_PROOF FAIL") -or $agentErr.Contains("AGENT_GUI_PROOF FAIL")
WLog "AGENT_GUI_PROOF_PASS_LINE=$hasProofPass FAIL_LINE=$hasProofFail"

$gateFileCounts = "FAIL_CLOSED"
$gateDiffReview = "FAIL_CLOSED"
if (($agentExit -eq 0) -and $hasProofPass) {
  $gateFileCounts = "RUNTIME_REACHED"
  $gateDiffReview = "RUNTIME_REACHED"
} elseif ($hasProofFail) {
  $gateFileCounts = "FAIL_CLOSED"
  $gateDiffReview = "FAIL_CLOSED"
} else {
  $gateFileCounts = "FAIL_CLOSED_NOT_RUN"
  $gateDiffReview = "FAIL_CLOSED_NOT_RUN"
}

WLog "LAUNCH tip GUI"
Remove-Item $Stdout,$Stderr -ErrorAction SilentlyContinue
$env:RAWRXD_GUI = "1"
Remove-Item Env:RAWRXD_HEADLESS -ErrorAction SilentlyContinue
$p = Start-Process -FilePath $TipExe -WorkingDirectory (Split-Path $TipExe) `
  -RedirectStandardOutput $Stdout -RedirectStandardError $Stderr `
  -PassThru -WindowStyle Normal
WLog "PID=$($p.Id)"

$hwnd = [int64]0
$deadline = (Get-Date).AddSeconds(75)
while ((Get-Date) -lt $deadline) {
  if ($p.HasExited) {
    WLog "FAIL_CLOSED early_exit=$($p.ExitCode)"
    break
  }
  $hwnd = [TipUiPhase7b]::FindMainByPid([uint32]$p.Id, $ClassName)
  if ($hwnd -ne 0) { break }
  Start-Sleep -Milliseconds 250
}
$hwndHex = $hwnd.ToString("X")
WLog "MAIN_HWND=0x$hwndHex"

$gateChat = "FAIL_CLOSED_NOT_RUN"
$gateModel = "FAIL_CLOSED_NOT_RUN"
$gateSettings = "FAIL_CLOSED_NOT_RUN"
$gateBgTasks = "FAIL_CLOSED_NOT_WIRED_MENU"
$gateGitDiff = "FAIL_CLOSED_NOT_RUN"
$comboBefore = -1
$comboAfter = -1
$childCount0 = 0
$childCount1 = 0
$settingsWnd = 0
$taskRunnerWnd = 0
$postChat = 0
$postSettings = 0
$postDiff = 0
$postAgent = 0

if ($hwnd -eq 0) {
  WLog "MAIN_HWND missing - GUI gates FAIL_CLOSED"
  $gateChat = "FAIL_CLOSED"
  $gateModel = "FAIL_CLOSED"
  $gateSettings = "FAIL_CLOSED"
  $gateGitDiff = "FAIL_CLOSED"
} else {
  $kids0 = [TipUiPhase7b]::DumpChildren($hwnd)
  $childCount0 = $kids0.Count
  $comboBefore = [TipUiPhase7b]::ComboItemCount($hwnd)
  $kids0 | Set-Content $ChildDump
  WLog "CHILD_COUNT_BASE=$childCount0 COMBO_MAX=$comboBefore"

  $postChat = [int][TipUiPhase7b]::PostCmd($hwnd, [uint32]$WM_COMMAND, $ID_CHAT)
  WLog "PostMessage chat 3007 ok=$postChat"
  Start-Sleep -Seconds 2
  $postAgent = [int][TipUiPhase7b]::PostCmd($hwnd, [uint32]$WM_COMMAND, $ID_AGENT_PANEL)
  WLog "PostMessage agent_panel 7057 ok=$postAgent"
  Start-Sleep -Seconds 2

  $kids1 = [TipUiPhase7b]::DumpChildren($hwnd)
  $childCount1 = $kids1.Count
  $comboAfter = [TipUiPhase7b]::ComboItemCount($hwnd)
  Add-Content $ChildDump ""
  Add-Content $ChildDump "--- after chat/agent toggle ---"
  $kids1 | Add-Content $ChildDump
  WLog "CHILD_COUNT_AFTER=$childCount1 COMBO_MAX=$comboAfter"

  if ($postChat -eq 1) {
    if (($childCount1 -gt $childCount0) -or ($comboAfter -ge 0)) {
      $gateChat = "RUNTIME_PARTIAL"
    } else {
      $gateChat = "RUNTIME_REACHED_POST_ONLY"
    }
  } else {
    $gateChat = "FAIL_CLOSED"
  }

  if ($comboAfter -gt 0) {
    $gateModel = "RUNTIME_REACHED"
  } elseif ($comboAfter -eq 0) {
    $gateModel = "RUNTIME_PARTIAL_EMPTY_COMBO"
  } elseif ($comboAfter -ge 0) {
    $gateModel = "RUNTIME_PARTIAL"
  } else {
    $gateModel = "FAIL_CLOSED_NO_COMBO"
  }

  $postSettings = [int][TipUiPhase7b]::PostCmd($hwnd, [uint32]$WM_COMMAND, $ID_SETTINGS)
  WLog "PostMessage settings 5016 ok=$postSettings"
  Start-Sleep -Seconds 1
  [void][TipUiPhase7b]::PostCmd($hwnd, [uint32]$WM_COMMAND, $ID_SETTINGS_T1)
  Start-Sleep -Seconds 2
  $settingsHits = @([TipUiPhase7b]::FindTopByPid([uint32]$p.Id, "Settings"))
  $settingsHits += @([TipUiPhase7b]::FindTopByPid([uint32]$p.Id, "Preferences"))
  $settingsWnd = $settingsHits.Count
  $settingsHits | Set-Content (Join-Path $OutDir "logs\settings_windows.txt")
  WLog "SETTINGS_TOPLEVEL_HITS=$settingsWnd"
  if (($postSettings -eq 1) -and ($settingsWnd -gt 0)) {
    $gateSettings = "RUNTIME_REACHED"
  } elseif ($postSettings -eq 1) {
    $gateSettings = "RUNTIME_REACHED_POST_ONLY"
  } else {
    $gateSettings = "FAIL_CLOSED"
  }

  $postDiff = [int][TipUiPhase7b]::PostCmd($hwnd, [uint32]$WM_COMMAND, $ID_GITDIFF)
  WLog "PostMessage gitdiff 11700 ok=$postDiff"
  Start-Sleep -Seconds 2
  if ($postDiff -eq 1) {
    $gateGitDiff = "RUNTIME_REACHED_POST_ONLY"
  } else {
    $gateGitDiff = "FAIL_CLOSED"
  }

  if ([TipUiPhase7b]::HasClassOnPid([uint32]$p.Id, "RawrXD_TaskRunner")) {
    $gateBgTasks = "RUNTIME_REACHED"
    $taskRunnerWnd = 1
  } else {
    $gateBgTasks = "FAIL_CLOSED_NOT_WIRED_MENU"
  }
}

if ($p -and (-not $p.HasExited)) {
  WLog "STOP tip GUI pid=$($p.Id)"
  Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
  Start-Sleep -Seconds 1
}

$shaAfter = (Get-FileHash -Algorithm SHA256 -Path $TipExe).Hash
$shaMatch = [int]($shaAfter -eq $ExpectSha)
$asof = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
WLog "TIP_SHA_AFTER=$shaAfter MATCH=$shaMatch"

$out = New-Object System.Text.StringBuilder
[void]$out.AppendLine("EVIDENCE=WIN32IDE_UI_COMPLETION_PHASE7_001")
[void]$out.AppendLine("PHASE=7_UI_COMPLETION")
[void]$out.AppendLine("ASOF_UTC=$asof")
[void]$out.AppendLine("TIP_EXE=$TipExe")
[void]$out.AppendLine("TIP_SHA=$sha")
[void]$out.AppendLine("TIP_SHA_AFTER=$shaAfter")
[void]$out.AppendLine("TIP_SHA_MATCH=$shaMatch")
[void]$out.AppendLine("GHOSTTEXT_WITNESS_B421=$WitnessB421")
[void]$out.AppendLine("GHOSTTEXT_ABSORB=NOT_AUTHORIZED")
[void]$out.AppendLine("NO_TIP_COPY=1")
[void]$out.AppendLine("MAIN_HWND=0x$hwndHex")
[void]$out.AppendLine("CHILD_COUNT_BASE=$childCount0")
[void]$out.AppendLine("CHILD_COUNT_AFTER=$childCount1")
[void]$out.AppendLine("COMBO_BEFORE=$comboBefore")
[void]$out.AppendLine("COMBO_AFTER=$comboAfter")
[void]$out.AppendLine("POST_CHAT_3007=$postChat")
[void]$out.AppendLine("POST_AGENT_7057=$postAgent")
[void]$out.AppendLine("POST_SETTINGS_5016=$postSettings")
[void]$out.AppendLine("POST_GITDIFF_11700=$postDiff")
[void]$out.AppendLine("SETTINGS_TOPLEVEL_HITS=$settingsWnd")
[void]$out.AppendLine("TASKRUNNER_HWND=$taskRunnerWnd")
[void]$out.AppendLine("AGENT_GUI_PROOF_EXIT=$agentExit")
[void]$out.AppendLine("AGENT_GUI_PROOF_PASS_LINE=$hasProofPass")
[void]$out.AppendLine("")
[void]$out.AppendLine("GATE_CHAT_PANEL=$gateChat")
[void]$out.AppendLine("GATE_DIFF_REVIEW=$gateDiffReview")
[void]$out.AppendLine("GATE_FILE_COUNTS=$gateFileCounts")
[void]$out.AppendLine("GATE_BACKGROUND_TASKS_UI=$gateBgTasks")
[void]$out.AppendLine("GATE_MODEL_SELECTOR=$gateModel")
[void]$out.AppendLine("GATE_SETTINGS=$gateSettings")
[void]$out.AppendLine("GATE_GITDIFF_SIDEBYSIDE=$gateGitDiff")
[void]$out.AppendLine("")
[void]$out.AppendLine("UI_ACCEPTANCE_PASS=0")
[void]$out.AppendLine("RUNTIME_PASS=0")
[void]$out.AppendLine("CERTIFIED=0")
[void]$out.AppendLine("PROMOTE=0")
[void]$out.AppendLine("TIP_CLIMB=HOLD")
[void]$out.AppendLine("NO_INVENT_PASS=1")
[void]$out.AppendLine("NOTE=PostMessage success != E2E UI PASS; agent-gui-proof PASS elevates file/diff to RUNTIME_REACHED only")
[void]$out.AppendLine("NOTE2=showTaskRunnerDialog has no Commands.cpp menu case on product tip - FAIL_CLOSED_NOT_WIRED_MENU")
[void]$out.AppendLine("NOTE3=GhostText B421 witness only; absorb NOT_AUTHORIZED; tip freeze 748B unchanged")
[IO.File]::WriteAllText((Join-Path $OutDir "SUMMARY.txt"), $out.ToString())
WLog "SUMMARY written"
WLog "END"
exit 0
