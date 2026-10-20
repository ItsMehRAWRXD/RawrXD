[CmdletBinding()]
param(
    [string]$CandidateRoot = $env:RAWRXD_MUTATION_ROOT,
    [string]$BuildDirectory = '_s12_parity_build',
    [ValidateRange(1, 64)]
    [int]$Parallel = 8
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($CandidateRoot)) { throw 'CandidateRoot or RAWRXD_MUTATION_ROOT is required.' }
$candidate = (Resolve-Path -LiteralPath $CandidateRoot).Path
$prefix = [IO.Path]::GetFullPath($candidate).TrimEnd('\') + '\'
$source = Join-Path $candidate 'rawrxd'
if (-not (Test-Path -LiteralPath (Join-Path $source 'CMakeLists.txt') -PathType Leaf)) { throw 'The candidate RawrXD CMake project is missing.' }
$build = if ([IO.Path]::IsPathRooted($BuildDirectory)) { [IO.Path]::GetFullPath($BuildDirectory) } else { [IO.Path]::GetFullPath((Join-Path $candidate $BuildDirectory)) }
if (-not $build.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or $build -eq $source -or $build.StartsWith($source.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase)) {
    throw 'BuildDirectory must be inside the candidate and outside its source directory.'
}
$current = $build
while ($current -and $current.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) {
    if (Test-Path -LiteralPath $current) {
        $item = Get-Item -LiteralPath $current -Force
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Candidate build path contains a reparse point: $current" }
    }
    $current = Split-Path -Parent $current
}

function Assert-CacheSource([string]$CachePath, [string]$ExpectedSource) {
    if (-not (Test-Path -LiteralPath $CachePath -PathType Leaf)) { return }
    $cache = [IO.File]::ReadAllText($CachePath)
    $sourceMatch = [regex]::Match($cache, '(?m)^CMAKE_HOME_DIRECTORY:INTERNAL=([^\r\n]+)')
    if (-not $sourceMatch.Success -or [IO.Path]::GetFullPath($sourceMatch.Groups[1].Value) -ine [IO.Path]::GetFullPath($ExpectedSource)) {
        throw 'CMake cache belongs to a different source checkout.'
    }
}

$cachePath = Join-Path $build 'CMakeCache.txt'
Assert-CacheSource $cachePath $source
$cmake = (Get-Command cmake -ErrorAction Stop).Source
$ninja = (Get-Command ninja -ErrorAction Stop).Source
$toolchainVariables = @('PATH', 'INCLUDE', 'LIB', 'LIBPATH', 'VSCMD_ARG_TGT_ARCH', 'VSCMD_ARG_HOST_ARCH', 'VCToolsInstallDir', 'VCINSTALLDIR', 'VSINSTALLDIR', 'WindowsSdkDir', 'WindowsSDKVersion', 'UniversalCRTSdkDir', 'UCRTVersion')
$savedEnvironment = @{}
foreach ($name in $toolchainVariables) { $savedEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process') }
try {
    if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue) -or -not $env:INCLUDE -or -not $env:LIB) {
        $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio/Installer/vswhere.exe'
        if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) { throw 'Visual Studio discovery is unavailable. Run from an x64 Developer PowerShell.' }
        $installation = @(& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath)
        if ($LASTEXITCODE -ne 0 -or $installation.Count -ne 1) { throw 'Unable to discover an MSVC x64 toolchain.' }
        $devCommand = Join-Path $installation[0] 'Common7/Tools/VsDevCmd.bat'
        if (-not (Test-Path -LiteralPath $devCommand -PathType Leaf)) { throw 'Visual Studio developer environment script is missing.' }
        $environmentLines = @(& $env:ComSpec /d /c ('call "{0}" -no_logo -arch=amd64 -host_arch=amd64 >nul && set' -f $devCommand) 2>&1)
        if ($LASTEXITCODE -ne 0) { throw 'Unable to initialize the MSVC developer environment.' }
        foreach ($line in $environmentLines) {
            $separator = ([string]$line).IndexOf('=')
            if ($separator -lt 1) { continue }
            $name = ([string]$line).Substring(0, $separator)
            if ($name -in $toolchainVariables) { [Environment]::SetEnvironmentVariable($name, ([string]$line).Substring($separator + 1), 'Process') }
        }
    }
    $compiler = (Get-Command cl.exe -ErrorAction Stop).Source
    Write-Output "CANDIDATE_SOURCE=$source"
    Write-Output "CANDIDATE_BUILD=$build"
    $configureArguments = @(
        '-S', $source, '-B', $build, '-G', 'Ninja',
        "-DCMAKE_MAKE_PROGRAM=$ninja",
        '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_EXPORT_COMPILE_COMMANDS=ON',
        '-DRAWR_ENABLE_VULKAN=ON', '-DBUILD_DEEP2_END_TO_END_BENCH=ON',
        '-DRAWRXD_BUILD_RAWRENGINE=OFF', '-DRAWRXD_BUILD_WIN32IDE=ON'
    )
    & $cmake @configureArguments
    if ($LASTEXITCODE -ne 0) { throw "Candidate CMake configuration failed with exit $LASTEXITCODE." }
    Assert-CacheSource $cachePath $source
    $compileCommands = Get-Content -LiteralPath (Join-Path $build 'compile_commands.json') -Raw | ConvertFrom-Json
    $engineSources = [Collections.Generic.List[string]]::new()
    foreach ($relative in @('src/deep2/vulkan_compute.cpp', 'src/deep2/Deep2Engine.cpp', 'src/deep2/Deep2Engine_GpuForward.cpp', 'src/deep2/deep2_end_to_end_bench.cpp')) {
        $expectedFile = [IO.Path]::GetFullPath((Join-Path $source $relative))
        $expectedTarget = if ($relative -eq 'src/deep2/deep2_end_to_end_bench.cpp') { 'deep2_end_to_end_bench' } else { 'InferenceEngine' }
        $targetOutput = "CMakeFiles/$expectedTarget.dir/"
        $entries = @($compileCommands | Where-Object {
            [IO.Path]::GetFullPath($_.file) -ieq $expectedFile -and ([string]$_.command).Replace('\', '/').Contains($targetOutput)
        })
        if ($entries.Count -ne 1) { throw "Candidate compile graph must contain exactly one entry for $relative." }
        if (-not [IO.Path]::GetFullPath($entries[0].directory).StartsWith($build.TrimEnd('\') + '\', [StringComparison]::OrdinalIgnoreCase) -and [IO.Path]::GetFullPath($entries[0].directory) -ine $build) { throw 'Candidate compile graph uses another build directory.' }
        [void]$engineSources.Add($expectedFile)
    }
    & $cmake --build $build --config Release --target deep2_end_to_end_bench --parallel $Parallel
    if ($LASTEXITCODE -ne 0) { throw "Candidate CMake build failed with exit $LASTEXITCODE." }
    $executable = Join-Path $build 'bin/deep2_end_to_end_bench.exe'
    if (-not (Test-Path -LiteralPath $executable -PathType Leaf)) { throw 'Candidate build did not produce deep2_end_to_end_bench.exe.' }
    $receipt = [ordered]@{
        schema = 'RAWRXD_DEEP2_CANDIDATE_BUILD_001'
        generated_utc = [DateTime]::UtcNow.ToString('o')
        source_root = $source
        build_root = $build
        compiler = $compiler
        executable = $executable
        executable_sha256 = (Get-FileHash -LiteralPath $executable).Hash
        engine_sources = @($engineSources)
        benchmark_launched = $false
    }
    $receiptPath = Join-Path $build 'candidate_build.json'
    [IO.File]::WriteAllText($receiptPath, ($receipt | ConvertTo-Json -Depth 6), [Text.UTF8Encoding]::new($false))
    Write-Output "CANDIDATE_BUILD_RECEIPT=$receiptPath"
    Write-Output ('CANDIDATE_BUILD_JSON=' + ($receipt | ConvertTo-Json -Depth 6 -Compress))
    Write-Output 'CANDIDATE_BUILD=PASS'
} finally {
    foreach ($name in $toolchainVariables) { [Environment]::SetEnvironmentVariable($name, $savedEnvironment[$name], 'Process') }
}
