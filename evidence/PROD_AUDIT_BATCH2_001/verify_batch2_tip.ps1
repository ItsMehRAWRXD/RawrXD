#Requires -Version 5.1
# PROD_AUDIT_BATCH2_001 — tip string/runtime probe for gates 19/20/22/27/28
# Fail-closed: SOURCE_WIRED != RUNTIME_REACHED; NOT_RUN != PASS; PROMOTE=0
$ErrorActionPreference = 'Continue'
$OutDir = 'F:\rawrxd\evidence\PROD_AUDIT_BATCH2_001'
$TipExe = 'F:\rawrxd\build_modelroute\bin\Release\RawrXD-Win32IDE-Native.exe'
$Seal = 'CB34EF4E1A3C964ADEC18F02ABBE605B85CB83F10961BCA6A9DB2D812FC0C6FB'
$Receipt = Join-Path $OutDir 'VERIFY_RECEIPT.md'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Has-Ascii([byte[]]$bytes, [string]$needle) {
  $ascii = [Text.Encoding]::ASCII.GetString($bytes)
  return $ascii.Contains($needle)
}

if (-not (Test-Path -LiteralPath $TipExe)) {
  @"
# VERIFY_RECEIPT PROD_AUDIT_BATCH2_001
ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))
TIP_EXE=$TipExe
TIP_PRESENT=0
DISPOSITION=FAIL_CLOSED_TIP_EXE_MISSING
PROMOTE=0
CERTIFIED=0
TIP_CLIMB=HOLD
SEAL_AUTHORITY_TOUCHED=0
"@ | Set-Content -LiteralPath $Receipt -Encoding UTF8
  exit 2
}

$sha = (Get-FileHash -LiteralPath $TipExe -Algorithm SHA256).Hash
$bytes = [IO.File]::ReadAllBytes($TipExe)
$gate27 = Has-Ascii $bytes 'Build Project'
$gate28 = Has-Ascii $bytes 'Test Project'
$gate19 = (Has-Ascii $bytes 'sha256') -or (Has-Ascii $bytes 'SHA256') -or (Has-Ascii $bytes 'BCryptHash')
$gate22 = Has-Ascii $bytes 'ide_session'
# DocumentBuffer is a C++ type name — often mangled; probe persist/session strings
$gate20 = (Has-Ascii $bytes 'persistActive') -or (Has-Ascii $bytes 'DocumentBuffer') -or (Has-Ascii $bytes 'm_documentBuffers')

# SHA round-trip of binary save path is in-process (Win32IDE::saveFile). Without a
# UI automation closer here, mark RUNTIME as NOT_RUN for 19/20/22 unless the
# local session file already exists from a prior real IDE run.
$sessionPath = Join-Path $env:LOCALAPPDATA 'RawrXD\ide_session.json'
$sessionExists = Test-Path -LiteralPath $sessionPath
$sessionBytes = 0
if ($sessionExists) { $sessionBytes = (Get-Item -LiteralPath $sessionPath).Length }

$lines = @(
  '# VERIFY_RECEIPT PROD_AUDIT_BATCH2_001',
  "ASOF_UTC=$((Get-Date).ToUniversalTime().ToString('o'))",
  "TIP_EXE=$TipExe",
  "TIP_SHA256=$sha",
  "SEAL_AUTHORITY_SHA256=$Seal",
  'SEAL_AUTHORITY_TOUCHED=0',
  'PROMOTE=0',
  'CERTIFIED=0',
  'TIP_CLIMB=HOLD',
  'INVENT_PASS=0',
  '',
  '## String / image probes (tip EXE)',
  "| Gate | Probe | Present |",
  "| --- | --- | --- |",
  "| 19 | sha256/BCrypt markers | $(if($gate19){'1'}else{'0'}) |",
  "| 20 | DocumentBuffer/persist markers | $(if($gate20){'1'}else{'0'}) |",
  "| 22 | ide_session | $(if($gate22){'1'}else{'0'}) |",
  "| 27 | Build Project | $(if($gate27){'1'}else{'0'}) |",
  "| 28 | Test Project | $(if($gate28){'1'}else{'0'}) |",
  '',
  '## Runtime observations',
  "LOCAL_IDE_SESSION_JSON=$sessionPath",
  "LOCAL_IDE_SESSION_EXISTS=$(if($sessionExists){'1'}else{'0'})",
  "LOCAL_IDE_SESSION_BYTES=$sessionBytes",
  'SHA_ROUNDTRIP_HARNESS=NOT_RUN',
  'NOTE=Binary save SHA round-trip lives in Win32IDE::saveFile; this script does not invent PASS without exercising that path.',
  '',
  '## Disposition (honest)',
  'SOURCE_WIRED markers above are image evidence only.',
  'RUNTIME_REACHED requires product path exercise; NOT_RUN != PASS.'
)
$lines -join "`n" | Set-Content -LiteralPath $Receipt -Encoding UTF8
Write-Output "TIP_SHA256=$sha"
Write-Output "G19=$([int]$gate19) G20=$([int]$gate20) G22=$([int]$gate22) G27=$([int]$gate27) G28=$([int]$gate28)"
Write-Output "SESSION_EXISTS=$([int]$sessionExists) RECEIPT=$Receipt"
