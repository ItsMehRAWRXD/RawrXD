# PRODUCT_BINARY_SEAL_001 â€” Native GhostText capture (candidate-only)
# Adapts F_GHOSTTEXT_CURRENT_BUILD_AB_RUNTIME_001/Capture-NativeGhostTextDebug.ps1
# Clean tip may lack WIP GHOSTTEXT_ debug markers â€” record actual behavior. PROMOTE=0
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\HARNESS_RECOVERY_AND_OS_FORENSICS_001'
$CandExe = 'F:\rawrxd\.worktrees\product_seal_clean_a5ae60ef_build\bin\RawrXD-Win32IDE-Native.exe'
$ExpectCand = 'CB34EF4E1A3C964ADEC18F02ABBE605B85CB83F10961BCA6A9DB2D812FC0C6FB'
$CaptureFile = Join-Path $OutDir 'logs_ghosttext\native_ghosttext_capture.txt'
$CaptureScript = 'F:\rawrxd\evidence\F_GHOSTTEXT_CURRENT_BUILD_AB_RUNTIME_001\Capture-NativeGhostTextDebug.ps1'

New-Item -ItemType Directory -Force -Path (Split-Path $CaptureFile) | Out-Null

$sha = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash
if ($sha -ne $ExpectCand) {
  @"
GATE=GHOSTTEXT_RUNTIME_NATIVE_CANDIDATE
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
DISPOSITION=FAIL_CLOSED_SHA_MISMATCH
RUNTIME_PASS=0
CANDIDATE_SHA=$sha
EXPECT_SHA=$ExpectCand
INVENT_PASS=0
PROMOTE=0
AUTHORITY_PRODUCT_BINARY=NOT_VERIFIED
"@ | Set-Content (Join-Path $OutDir 'GHOSTTEXT_RUNTIME_RECEIPT.md')
  exit 2
}

Get-Process | Where-Object { $_.ProcessName -like 'RawrXD-Win32IDE*' } |
  ForEach-Object { Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2

# Pre-check: clean tip EXE may not contain GHOSTTEXT_ marker strings (WIP-only)
$bytes = [IO.File]::ReadAllBytes($CandExe)
$ascii = [Text.Encoding]::ASCII.GetString($bytes)
$hasGhostMarker = $ascii.Contains('GHOSTTEXT_')
$hasGhostText = $ascii.Contains('GhostText')
$hasDebugId = $true # IDC_OUTPUT_EDIT_DEBUG=1014 present in tip sources

& $CaptureScript -Executable $CandExe -DurationSeconds 45 -CaptureFile $CaptureFile
$capExit = $LASTEXITCODE

$captureText = ''
if (Test-Path $CaptureFile) { $captureText = Get-Content $CaptureFile -Raw -ErrorAction SilentlyContinue }
$debugLatest = ''
$debugPath = $CaptureFile + '.debug.latest'
if (Test-Path $debugPath) { $debugLatest = Get-Content $debugPath -Raw -ErrorAction SilentlyContinue }

$sawProcess = [int]($captureText -match 'PROCESS_STARTED')
$sawDebugHwnd = [int]($captureText -match 'DEBUG_HWND=')
$sawEditorHwnd = [int]($captureText -match 'EDITOR_HWND=')
$sawGhostMarkerRuntime = [int](($captureText + $debugLatest) -match 'GHOSTTEXT_')
$exitedClean = [int]($captureText -match 'PROCESS_EXITED|NORMAL_CLOSE_REQUESTED|CAPTURE_WINDOW_ENDED')
$forceHeld = [int]($captureText -match 'HELD_NO_FORCE|PROCESS_REMAINS')

# Fail-closed: do not invent GhostText PASS if marker/stream not observed
$disposition = 'NOT_VERIFIED'
$runtimePass = 0
if ($sawProcess -ne 1) {
  $disposition = 'FAIL_CLOSED_LAUNCH'
} elseif ($sawGhostMarkerRuntime -eq 1) {
  $disposition = 'GHOSTTEXT_MARKER_OBSERVED'
  $runtimePass = 0  # observation â‰  product accept / Gate6 transfer
} elseif ($sawDebugHwnd -eq 1 -or $sawEditorHwnd -eq 1) {
  $disposition = 'UI_CONTROLS_PRESENT_NO_GHOSTTEXT_MARKER'
} elseif ($hasGhostText -and -not $hasGhostMarker) {
  $disposition = 'CLEAN_TIP_GHOSTTEXT_WIRED_WITHOUT_WIP_DEBUG_MARKERS'
} else {
  $disposition = 'NOT_OBSERVED'
}

$candAfter = (Get-FileHash -LiteralPath $CandExe -Algorithm SHA256).Hash

@"
GATE=GHOSTTEXT_RUNTIME_NATIVE_CANDIDATE
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))
DISPOSITION=$disposition
RUNTIME_PASS=$runtimePass
CANDIDATE_SHA=$candAfter
SHA_MATCH_EXPECT=$([int]($candAfter -eq $ExpectCand))
CAPTURE_EXIT=$capExit
PROCESS_STARTED=$sawProcess
DEBUG_HWND_SEEN=$sawDebugHwnd
EDITOR_HWND_SEEN=$sawEditorHwnd
GHOSTTEXT_MARKER_IN_EXE=$([int]$hasGhostMarker)
GHOSTTEXT_STRING_IN_EXE=$([int]$hasGhostText)
GHOSTTEXT_MARKER_AT_RUNTIME=$sawGhostMarkerRuntime
CAPTURE_ENDED=$exitedClean
FORCE_TERMINATION_HELD=$forceHeld
CAPTURE_FILE=$CaptureFile
NOTE=Clean tip may lack WIP GhostText debug markers (GHOSTTEXT_*). Gate6/tool PASS not transferred.
INVENT_PASS=0
PROMOTE=0
CERTIFIED=0
AUTHORITY_PRODUCT_BINARY=NOT_VERIFIED
BUILD_SCOPE=CANDIDATE_ONLY
TIP_CLIMB=HOLD
"@ | Set-Content (Join-Path $OutDir 'GHOSTTEXT_RUNTIME_RECEIPT.md')

Write-Output "GHOSTTEXT disposition=$disposition runtimePass=$runtimePass"
exit 0

