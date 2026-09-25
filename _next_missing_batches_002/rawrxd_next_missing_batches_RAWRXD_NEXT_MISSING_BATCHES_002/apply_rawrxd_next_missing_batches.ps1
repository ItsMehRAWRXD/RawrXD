param(
    [Parameter(Mandatory=$true)][string]$RepoRoot,
    [switch]$PatchStrictCMake
)

$ErrorActionPreference = 'Stop'
$drop = Split-Path -Parent $MyInvocation.MyCommand.Path
$srcRoot = Join-Path $drop 'src'

$copyMap = @(
    @{ From='deep2/special_graph/FleetSpecialGraph.hpp'; To='src/deep2/special_graph/FleetSpecialGraph.hpp' },
    @{ From='deep2/special_graph/FleetSpecialGraph.cpp'; To='src/deep2/special_graph/FleetSpecialGraph.cpp' },
    @{ From='deep2/special_graph/FleetSpecialGraphExecutor.hpp'; To='src/deep2/special_graph/FleetSpecialGraphExecutor.hpp' },
    @{ From='deep2/special_graph/FleetSpecialGraphExecutor.cpp'; To='src/deep2/special_graph/FleetSpecialGraphExecutor.cpp' },
    @{ From='agentic/DualGpuIndependentAgentScheduler.hpp'; To='src/agentic/DualGpuIndependentAgentScheduler.hpp' },
    @{ From='agentic/DualGpuIndependentAgentScheduler.cpp'; To='src/agentic/DualGpuIndependentAgentScheduler.cpp' },
    @{ From='core/HexMagResidencyAuthority.hpp'; To='src/core/HexMagResidencyAuthority.hpp' },
    @{ From='core/HexMagResidencyAuthority.cpp'; To='src/core/HexMagResidencyAuthority.cpp' },
    @{ From='screenpilot/ScreenPilotToolAuthorityBridge.hpp'; To='src/screenpilot/ScreenPilotToolAuthorityBridge.hpp' },
    @{ From='screenpilot/ScreenPilotToolAuthorityBridge.cpp'; To='src/screenpilot/ScreenPilotToolAuthorityBridge.cpp' },
    @{ From='agentic/MultiAgentMergeAuthority.hpp'; To='src/agentic/MultiAgentMergeAuthority.hpp' },
    @{ From='agentic/MultiAgentMergeAuthority.cpp'; To='src/agentic/MultiAgentMergeAuthority.cpp' }
)

foreach ($m in $copyMap) {
    $from = Join-Path $srcRoot $m.From
    $to = Join-Path $RepoRoot $m.To
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $to) | Out-Null
    Copy-Item -Force $from $to
    Write-Host "COPIED $($m.To)"
}

$scriptDest = Join-Path $RepoRoot 'scripts/rawrxd_closure'
New-Item -ItemType Directory -Force -Path $scriptDest | Out-Null
Copy-Item -Force (Join-Path $drop 'scripts/certify_clean_clone_release.ps1') $scriptDest
Copy-Item -Force (Join-Path $drop 'scripts/audit_known_open_gaps.ps1') $scriptDest

if ($PatchStrictCMake) {
    $cmake = Join-Path $RepoRoot 'win32ide_strict/CMakeLists.txt'
    if (-not (Test-Path $cmake)) { throw "Strict CMake file not found: $cmake" }
    $marker = 'RAWRXD_NEXT_MISSING_BATCHES_002_BEGIN'
    $text = Get-Content $cmake -Raw
    if ($text -notmatch [regex]::Escape($marker)) {
        $block = @"

# $marker
if(TARGET RawrXD-Win32IDE)
  target_sources(RawrXD-Win32IDE PRIVATE
    `${CMAKE_CURRENT_LIST_DIR}/../src/deep2/special_graph/FleetSpecialGraph.cpp
    `${CMAKE_CURRENT_LIST_DIR}/../src/deep2/special_graph/FleetSpecialGraphExecutor.cpp
    `${CMAKE_CURRENT_LIST_DIR}/../src/agentic/DualGpuIndependentAgentScheduler.cpp
    `${CMAKE_CURRENT_LIST_DIR}/../src/core/HexMagResidencyAuthority.cpp
    `${CMAKE_CURRENT_LIST_DIR}/../src/screenpilot/ScreenPilotToolAuthorityBridge.cpp
    `${CMAKE_CURRENT_LIST_DIR}/../src/agentic/MultiAgentMergeAuthority.cpp
  )
  target_include_directories(RawrXD-Win32IDE PRIVATE
    `${CMAKE_CURRENT_LIST_DIR}/../src
    `${CMAKE_CURRENT_LIST_DIR}/../include
  )
endif()
# RAWRXD_NEXT_MISSING_BATCHES_002_END
"@
        Add-Content -Path $cmake -Value $block
        Write-Host 'STRICT_CMAKE_PATCH=APPLIED'
    } else {
        Write-Host 'STRICT_CMAKE_PATCH=ALREADY_PRESENT'
    }
} else {
    Write-Host 'STRICT_CMAKE_PATCH=SKIPPED (use -PatchStrictCMake to append target_sources block)'
}

Write-Host 'RAWRXD_NEXT_MISSING_BATCHES_002_APPLY=PASS'
