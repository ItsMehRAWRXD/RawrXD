[CmdletBinding()]
param(
    [string]$BenchmarkExe,
    [string]$ShaderSpv,
    [string]$RgaExe,
    [string]$OutputDirectory,
    [ValidateRange(64, 2048)][int]$Rows = 1024,
    [ValidateRange(3, 100)][int]$Repetitions = 15,
    [ValidateSet('1', '2', '4', '8', '16')][int]$PadLocal = 1,
    [string]$CompetingBenchmarkExe = 'F:\wt_ide1\_s12_parity_build\bin\deep2_end_to_end_bench.exe'
)

$ErrorActionPreference = 'Stop'
$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not $BenchmarkExe) {
    $candidates = @(
        (Join-Path $repoRoot 'build_modelroute\bin\Release\deep2_uneven_tp_gemv.exe'),
        (Join-Path $repoRoot 'build_modelroute\bin\deep2_uneven_tp_gemv.exe')
    )
    $BenchmarkExe = $candidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
}
if (-not $ShaderSpv) {
    $ShaderSpv = Join-Path $repoRoot 'src\deep2\shaders\deep2_ops.spv'
}
if (-not $BenchmarkExe -or -not (Test-Path -LiteralPath $BenchmarkExe)) {
    throw 'Build deep2_uneven_tp_gemv first, or pass -BenchmarkExe.'
}
if (-not (Test-Path -LiteralPath $ShaderSpv)) {
    throw "Deep2 Vulkan shader SPIR-V was not found: $ShaderSpv"
}
if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repoRoot (Join-Path 'evidence' ('TP_UNEVEN_WIDTH_SWEEP_' + (Get-Date -Format 'yyyyMMdd-HHmmss')))
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

function Get-CompetingBenchmarkProcesses {
    if (-not $CompetingBenchmarkExe) { return @() }
    $expected = [System.IO.Path]::GetFullPath($CompetingBenchmarkExe)
    return @(Get-CimInstance Win32_Process | Where-Object {
        $_.Name -eq [System.IO.Path]::GetFileName($expected) -and
        $_.ExecutablePath -and
        [System.IO.Path]::GetFullPath($_.ExecutablePath) -ieq $expected
    })
}

$before = Get-CompetingBenchmarkProcesses
if ($before.Count -gt 0) {
    throw "Competing benchmark is running (PID $($before[0].ProcessId)); pause it before profiling."
}

$rgaVersion = '2.15'
$archiveSha256 = '1dd6fc63baa3ea00f0c4daf208b6139ca924566dd4305a77da0b6c5e52df2377'
$rgaRoot = Join-Path $env:LOCALAPPDATA 'RawrXD\tools\RGA-2.15'
if (-not $RgaExe) {
    $RgaExe = Get-ChildItem -Path $rgaRoot -Filter rga.exe -Recurse -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty FullName -First 1
}
if (-not $RgaExe) {
    $downloadRoot = Join-Path $env:LOCALAPPDATA 'RawrXD\downloads'
    New-Item -ItemType Directory -Path $downloadRoot -Force | Out-Null
    $archive = Join-Path $downloadRoot 'rga-windows-x64-2.15.zip'
    $url = 'https://github.com/GPUOpen-Tools/radeon_gpu_analyzer/releases/download/2.15/rga-windows-x64-2.15.zip'
    if (-not (Test-Path -LiteralPath $archive) -or
        (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant() -ne $archiveSha256) {
        Invoke-WebRequest -Uri $url -OutFile $archive
    }
    $actualSha256 = (Get-FileHash -Algorithm SHA256 -LiteralPath $archive).Hash.ToLowerInvariant()
    if ($actualSha256 -ne $archiveSha256) {
        throw "RGA release archive SHA-256 mismatch: expected $archiveSha256, got $actualSha256"
    }
    New-Item -ItemType Directory -Path $rgaRoot -Force | Out-Null
    $alreadyExtracted = Get-ChildItem -Path $rgaRoot -Filter rga.exe -Recurse -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $alreadyExtracted) {
        Expand-Archive -LiteralPath $archive -DestinationPath $rgaRoot -Force
    }
    $RgaExe = Get-ChildItem -Path $rgaRoot -Filter rga.exe -Recurse -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty FullName -First 1
}
if (-not $RgaExe -or -not (Test-Path -LiteralPath $RgaExe)) {
    throw 'RGA CLI was not found after checking PATH and the verified AMD package.'
}

$rgaVersionText = (& $RgaExe -v 2>&1 | Out-String).Trim()
$rgaHelpPath = Join-Path $OutputDirectory 'rga-vulkan-spv-help.txt'
(& $RgaExe -s vk-spv-offline -h 2>&1 | Out-String) | Set-Content -LiteralPath $rgaHelpPath -Encoding utf8

# deep2_ops.comp receives cols as a runtime push constant. Its ISA is the same
# for all swept widths; emit one shader disassembly per ASIC, not fake width-
# specific copies. RGA offline output is static compiler analysis, not a live
# GPU timeline capture.
$shaderHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $ShaderSpv).Hash.ToLowerInvariant()
$isaRecords = @()
foreach ($asic in @('gfx1201', 'gfx1101')) {
    $isaPath = Join-Path $OutputDirectory "deep2_ops.$asic.isa"
    $statsPath = Join-Path $OutputDirectory "deep2_ops.$asic.stats.csv"
    & $RgaExe -s vk-spv-offline -c $asic --comp $ShaderSpv --isa $isaPath -a $statsPath *> (Join-Path $OutputDirectory "rga-$asic.log")
    $rgaExit = $LASTEXITCODE
    if ($rgaExit -ne 0) {
        throw "RGA failed for $asic with exit code $rgaExit; see $(Join-Path $OutputDirectory "rga-$asic.log")."
    }
    $emittedIsa = Get-ChildItem -Path $OutputDirectory -Filter '*.isa' -File |
        Where-Object { $_.Name -like "*deep2_ops*$asic*" -or $_.Name -eq [System.IO.Path]::GetFileName($isaPath) } |
        Select-Object -First 1
    if (-not $emittedIsa) {
        $emittedIsa = Get-ChildItem -Path $OutputDirectory -Filter '*.isa' -File | Select-Object -Last 1
    }
    if (-not $emittedIsa) { throw "RGA exited successfully but produced no ISA file for $asic." }
    $emittedStats = Get-ChildItem -Path $OutputDirectory -Filter '*.stats_comp.csv' -File |
        Where-Object { $_.Name -match [regex]::Escape($asic) } |
        Select-Object -First 1
    if (-not $emittedStats) { throw "RGA exited successfully but produced no statistics CSV for $asic." }
    $isaRecords += [pscustomobject]@{
        Asic = $asic
        IsaPath = $emittedIsa.FullName
        StatsPath = $emittedStats.FullName
        ExitCode = $rgaExit
    }
}

$benchmarkLog = Join-Path $OutputDirectory 'width-sweep.log'
$benchmarkArgs = @('--sweep', '--rows', $Rows, '--reps', $Repetitions, '--pad-local', $PadLocal)
& $BenchmarkExe @benchmarkArgs *> $benchmarkLog
$benchmarkExit = $LASTEXITCODE
$after = Get-CompetingBenchmarkProcesses

$sourceFiles = [ordered]@{
    BENCHMARK_SOURCE = Join-Path $repoRoot 'tools\gpu_profiler\deep2_uneven_tp_gemv.cpp'
    VULKAN_SOURCE = Join-Path $repoRoot 'src\deep2\vulkan_compute.cpp'
    VULKAN_HEADER = Join-Path $repoRoot 'src\deep2\vulkan_compute.h'
    SHADER_SOURCE = Join-Path $repoRoot 'src\deep2\shaders\deep2_ops.comp'
    PROFILE_SCRIPT = $PSCommandPath
}

$receipt = [System.Collections.Generic.List[string]]::new()
$receipt.Add('BENCHMARK=DEEP2_UNEVEN_TP_GEMV_V4')
$receipt.Add("DATE_LOCAL=$((Get-Date).ToString('yyyy-MM-dd HH:mm:ss zzz'))")
$receipt.Add("BENCHMARK_EXE=$BenchmarkExe")
$receipt.Add("BENCHMARK_EXE_SHA256=$((Get-FileHash -Algorithm SHA256 -LiteralPath $BenchmarkExe).Hash.ToLowerInvariant())")
$receipt.Add("SHADER_SPV=$ShaderSpv")
$receipt.Add("SHADER_SPV_SHA256=$shaderHash")
$receipt.Add('BUILD_COMMAND=cmake --build build_modelroute --config Release --target deep2_uneven_tp_gemv -- /m:4')
foreach ($name in $sourceFiles.Keys) {
    $sourcePath = $sourceFiles[$name]
    if (-not (Test-Path -LiteralPath $sourcePath)) { throw "Receipt source is missing: $sourcePath" }
    $receipt.Add("${name}=$sourcePath")
    $receipt.Add("${name}_SHA256=$((Get-FileHash -Algorithm SHA256 -LiteralPath $sourcePath).Hash.ToLowerInvariant())")
}
$receipt.Add("RGA_VERSION=$rgaVersion")
$receipt.Add("RGA_EXE=$RgaExe")
$receipt.Add("RGA_VERSION_OUTPUT=$rgaVersionText")
$receipt.Add("RGA_ARCHIVE_SHA256=$archiveSha256")
$receipt.Add("ROWS=$Rows")
$receipt.Add("REPETITIONS=$Repetitions")
$receipt.Add("LOCAL_ZERO_PAD_MULTIPLE=$PadLocal")
$receipt.Add('LOCAL_WIDTH_RANGE=2032..2080')
$receipt.Add('SPLITS=EVEN_AND_RANK0_PLUS_ONE_RAGGED')
$receipt.Add('PADDING_METHOD=Benchmark-only: round physical weight-row stride up to PadLocal and zero-fill only the weight tail; input remains logical-width.')
$receipt.Add('ISA_VARIANT_NOTE=Shader width is a runtime push constant; one ISA output per ASIC covers all widths.')
$receipt.Add('RGA_MODE=vk-spv-offline; static compiler analysis, not live GPU timing')
foreach ($record in $isaRecords) {
    $receipt.Add("RGA_$($record.Asic)_EXIT_CODE=$($record.ExitCode)")
    $receipt.Add("RGA_$($record.Asic)_ISA=$($record.IsaPath)")
    $receipt.Add("RGA_$($record.Asic)_ISA_SHA256=$((Get-FileHash -Algorithm SHA256 -LiteralPath $record.IsaPath).Hash.ToLowerInvariant())")
    $receipt.Add("RGA_$($record.Asic)_STATS=$($record.StatsPath)")
    $receipt.Add("RGA_$($record.Asic)_STATS_SHA256=$((Get-FileHash -Algorithm SHA256 -LiteralPath $record.StatsPath).Hash.ToLowerInvariant())")
}
$receipt.Add("COMPETING_PROCESS_BEFORE=$($before.Count)")
$receipt.Add("BENCHMARK_EXIT_CODE=$benchmarkExit")
$receipt.Add("COMPETING_PROCESS_AFTER=$($after.Count)")
$receipt.Add("BENCHMARK_LOG=$benchmarkLog")
$receipt.Add("BENCHMARK_LOG_SHA256=$((Get-FileHash -Algorithm SHA256 -LiteralPath $benchmarkLog).Hash.ToLowerInvariant())")
if ($benchmarkExit -eq 0) {
    $passCases = (Select-String -LiteralPath $benchmarkLog -Pattern '^CPU_PARITY=PASS$').Count
    $gpuPassCases = (Select-String -LiteralPath $benchmarkLog -Pattern '^SINGLE_GPU_PARITY=PASS$').Count
    $paddingPassCases = (Select-String -LiteralPath $benchmarkLog -Pattern '^ZERO_PADDED_WEIGHT_TAILS=PASS$').Count
    $receipt.Add("CPU_PARITY_CASES=$passCases/98")
    $receipt.Add("SINGLE_GPU_PARITY_CASES=$gpuPassCases/98")
    $receipt.Add("ZERO_PADDED_WEIGHT_TAIL_CASES=$paddingPassCases/98")
    if ($passCases -eq 98 -and $gpuPassCases -eq 98 -and $paddingPassCases -eq 98) {
        $receipt.Add('MICROBENCH_RESULT=PASS')
    } else {
        $receipt.Add('MICROBENCH_RESULT=FAIL')
        $benchmarkExit = 5
    }
} else {
    $receipt.Add('MICROBENCH_RESULT=FAIL')
}
$receipt.Add('GATE_10=OPEN')
$receiptPath = Join-Path $OutputDirectory 'receipt.txt'
$receipt | Set-Content -LiteralPath $receiptPath -Encoding utf8
Get-Content -LiteralPath $receiptPath
if ($benchmarkExit -ne 0) { exit $benchmarkExit }
if ($after.Count -gt 0) { throw 'A competing GPU benchmark started during this run; inspect the receipt and repeat under isolation.' }
