param(
    [string]$RawrXDRoot = "F:\~dev\rawrxd"
)

$ErrorActionPreference = "Stop"
$Drop = Split-Path -Parent $MyInvocation.MyCommand.Path
$DstSrc = Join-Path $RawrXDRoot "src\agentic"
$DstTests = Join-Path $RawrXDRoot "tests"

New-Item -ItemType Directory -Force -Path $DstSrc | Out-Null
New-Item -ItemType Directory -Force -Path $DstTests | Out-Null

Copy-Item -Force (Join-Path $Drop "src\agentic\RawrXDAgenticE2E.hpp") $DstSrc
Copy-Item -Force (Join-Path $Drop "src\agentic\RawrXDAgenticE2E.cpp") $DstSrc
Copy-Item -Force (Join-Path $Drop "tests\rawrxd_agentic_e2e_gate.cpp") $DstTests
Copy-Item -Force (Join-Path $Drop "CMakeLists.agentic.snippet") $RawrXDRoot
Copy-Item -Force (Join-Path $Drop "INTEGRATION.cpp.snippet") $RawrXDRoot

Write-Host "RAWRXD_AGENTIC_E2E_001_SOURCE_DROP=PASS"
Write-Host "ROOT=$RawrXDRoot"
Write-Host "SOURCE=$DstSrc\RawrXDAgenticE2E.cpp"
Write-Host "HEADER=$DstSrc\RawrXDAgenticE2E.hpp"
Write-Host "GATE=$DstTests\rawrxd_agentic_e2e_gate.cpp"
Write-Host "NEXT=add CMakeLists.agentic.snippet to RawrXD-Win32IDE target, then wire INTEGRATION.cpp.snippet into Native Compile Test"
