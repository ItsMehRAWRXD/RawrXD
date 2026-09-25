param([Parameter(Mandatory=$true)][string]$RepoRoot)
$ErrorActionPreference = 'Stop'

$checks = @(
    @{ Id='PRODUCTION_PROFILER_STUB'; Path='src/deep2/ProductionProfiler.hpp'; Pattern='class\s+ProductionProfiler\s*\{\s*\};' },
    @{ Id='NVME_STREAM_STUB'; Path='src/deep2/NVMeStream.h'; Pattern='stub|class\s+NVMeStream\s*\{\s*\};' },
    @{ Id='BP16_STREAMER_STUB'; Path='src/deep2/BP16Streamer.hpp'; Pattern='stub|class\s+BP16Streamer\s*\{\s*\};' },
    @{ Id='COMPRESSED_KV_STUB'; Path='src/deep2/CompressedKVCache.h'; Pattern='stub|class\s+CompressedKVCache\s*\{\s*\};' },
    @{ Id='MARS_CONSTANT_SUCCESS'; Path='src/deep2/mars/MARSController.hpp'; Pattern='return\s+true\s*;' }
)

$open = 0
Write-Host '=== RAWRXD_KNOWN_OPEN_GAP_GUARD_001 ==='
foreach ($c in $checks) {
    $p = Join-Path $RepoRoot $c.Path
    if (-not (Test-Path $p)) {
        Write-Host "$($c.Id)=NOT_PRESENT"
        continue
    }
    $m = Select-String -Path $p -Pattern $c.Pattern -CaseSensitive:$false -ErrorAction SilentlyContinue
    if ($m) {
        ++$open
        Write-Host "$($c.Id)=OPEN"
    } else {
        Write-Host "$($c.Id)=CLOSED_OR_REQUIRES_RUNTIME_PROOF"
    }
}
Write-Host "KNOWN_OPEN_GAPS=$open"
Write-Host ("VERDICT=" + $(if ($open -eq 0) { 'PASS' } else { 'FAIL' }))
if ($open -ne 0) { exit 1 }
