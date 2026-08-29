# Generate-CertLadderManifest.ps1
# Emits ordered next-todos from evidence GATE files (no doc claims).
param(
    [string]$EvidenceRoot = "F:\~dev\rawrxd\evidence\DEEP2_PARITY_PROBE_001",
    [string]$OutDir = "g:\rawrxd\generated"
)

$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force -Path $OutDir, "g:\rawrxd\build\gate2" | Out-Null

$vs = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" `
    -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 `
    -property installationPath
$vcvars = Join-Path $vs "VC\Auxiliary\Build\vcvars64.bat"
$exe = "g:\rawrxd\build\gate2\rawrxd_cert_ladder_manifest.exe"
$json = Join-Path $OutDir "CertLadderManifest.json"
$board = Join-Path $OutDir "CertLadderTodos.txt"

cmd /c "`"$vcvars`" >nul && cl /nologo /EHsc /std:c++17 /O2 /I g:\rawrxd\src\core\self /Fe:$exe g:\rawrxd\tools\rawrxd_cert_ladder_manifest.cpp g:\rawrxd\src\core\self\RuntimeManifest.cpp && $exe `"$EvidenceRoot`" `"$json`" `"$board`""
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
Write-Host "DO_NOW board: $board"
