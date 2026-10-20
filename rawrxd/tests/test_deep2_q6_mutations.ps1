[CmdletBinding()]
param(
    [string]$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path,
    [string]$MutationScript = (Join-Path $PSScriptRoot '..\tools\mutate_qgemv_q6_algebra.ps1'),
    [string]$ReportPath = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Invoke-FixtureProcess([string]$Executable, [string[]]$Arguments, [hashtable]$EnvironmentOverrides = @{}) {
    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $Executable
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    foreach ($argument in $Arguments) { $startInfo.ArgumentList.Add($argument) }
    foreach ($key in $EnvironmentOverrides.Keys) { $startInfo.Environment[$key] = $EnvironmentOverrides[$key] }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) { throw "Unable to start $Executable" }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(60000)) {
            $process.Kill($true)
            $process.WaitForExit()
            throw "Fixture command timed out: $Executable"
        }
        return [pscustomobject]@{ exit_code = $process.ExitCode; stdout = $stdout.GetAwaiter().GetResult(); stderr = $stderr.GetAwaiter().GetResult() }
    } finally { $process.Dispose() }
}

function Assert-Condition([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
}

$sourceShader = Join-Path $RepoRoot 'rawrxd/src/deep2/shaders/deep2_qgemv_batch8row.comp'
$sourceSpirv = Join-Path $RepoRoot 'rawrxd/src/deep2/shaders/deep2_qgemv_batch8row.spv'
$sourceHash = (Get-FileHash -LiteralPath $sourceShader).Hash
$sourceSpirvHash = (Get-FileHash -LiteralPath $sourceSpirv).Hash
$sourceText = [IO.File]::ReadAllText($sourceShader)
$mutationPath = (Resolve-Path -LiteralPath $MutationScript).Path
$sdk = if ($env:VULKAN_SDK) { $env:VULKAN_SDK } else { 'C:\VulkanSDK\1.4.357.0' }
$compiler = Join-Path $sdk 'Bin/glslc.exe'
$validator = Join-Path $sdk 'Bin/spirv-val.exe'
$pwsh = (Get-Command pwsh -ErrorAction Stop).Source
foreach ($tool in @($compiler, $validator)) {
    if (-not (Test-Path -LiteralPath $tool -PathType Leaf)) { throw "Required shader tool is missing: $tool" }
}
$fixtureRoot = Join-Path ([IO.Path]::GetTempPath()) ('rawrxd_q6_mutation_tests_' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $fixtureRoot | Out-Null
$shaderRelative = 'rawrxd/src/deep2/shaders/deep2_qgemv_batch8row.comp'
$spirvRelative = 'rawrxd/src/deep2/shaders/deep2_qgemv_batch8row.spv'
$results = [System.Collections.Generic.List[object]]::new()
$utf8 = [Text.UTF8Encoding]::new($false)
try {
    $baselineSpirv = Join-Path $fixtureRoot 'baseline.spv'
    $compile = Invoke-FixtureProcess $compiler @('-O', '--target-env=vulkan1.2', '-fshader-stage=compute', $sourceShader, '-o', $baselineSpirv)
    Assert-Condition ($compile.exit_code -eq 0) ("Baseline compile failed: " + $compile.stderr)
    $validate = Invoke-FixtureProcess $validator @('--target-env', 'vulkan1.2', $baselineSpirv)
    Assert-Condition ($validate.exit_code -eq 0) ("Baseline validation failed: " + $validate.stderr)
    $baselineSpirvHash = (Get-FileHash -LiteralPath $baselineSpirv).Hash
    foreach ($variant in @('hoist_scale', 'half_load', 'hoist_scale_half_load', 'skip_unused_batch_rows', 'unknown_variant', 'missing_q6_function', 'compiler_failure', 'undeclared_spirv')) {
        $entry = [ordered]@{ name = $variant; pass = $false }
        try {
            $workspace = Join-Path $fixtureRoot $variant
            $shaderPath = Join-Path $workspace $shaderRelative
            $spirvPath = Join-Path $workspace $spirvRelative
            New-Item -ItemType Directory -Path (Split-Path -Parent $shaderPath) -Force | Out-Null
            $fixtureText = $sourceText
            if ($variant -eq 'missing_q6_function') { $fixtureText = $fixtureText.Replace('void q6kDot4(', 'void absentQ6Dot4(') }
            if ($variant -eq 'compiler_failure') { $fixtureText += "`nthis is deliberately invalid GLSL;`n" }
            [IO.File]::WriteAllText($shaderPath, $fixtureText, $utf8)
            Copy-Item -LiteralPath $baselineSpirv -Destination $spirvPath
            $beforeHash = (Get-FileHash -LiteralPath $shaderPath).Hash
            $environmentOverrides = @{
                RAWRXD_MUTATION_ROOT = $workspace
                RAWRXD_MUTATION_ALLOWED_FILES = if ($variant -eq 'undeclared_spirv') { $shaderRelative } else { "$shaderRelative;$spirvRelative" }
                RAWRXD_MUTATION_VARIANT = if ($variant -in @('missing_q6_function', 'compiler_failure', 'undeclared_spirv')) { 'hoist_scale' } else { $variant }
            }
            $mutation = Invoke-FixtureProcess $pwsh @('-NoProfile', '-File', $mutationPath) $environmentOverrides
            $entry.mutation_exit = $mutation.exit_code
            if ($variant -in @('unknown_variant', 'missing_q6_function', 'compiler_failure', 'undeclared_spirv')) {
                Assert-Condition ($mutation.exit_code -ne 0) 'Invalid fixture was accepted.'
                if ($variant -ne 'compiler_failure') {
                    Assert-Condition ((Get-FileHash -LiteralPath $shaderPath).Hash -ceq $beforeHash) 'Rejected input changed the fixture source.'
                }
                Assert-Condition ((Get-FileHash -LiteralPath $spirvPath).Hash -ceq $baselineSpirvHash) 'Rejected input replaced the existing SPIR-V.'
            } else {
                Assert-Condition ($mutation.exit_code -eq 0) ("Mutation failed: " + $mutation.stderr)
                $afterText = [IO.File]::ReadAllText($shaderPath)
                Assert-Condition ($afterText -cne $sourceText) 'Variant emitted the original shader without changes.'
                $expectsHoist = $variant -in @('hoist_scale', 'hoist_scale_half_load')
                $expectsHalfLoad = $variant -in @('half_load', 'hoist_scale_half_load')
                Assert-Condition ($afterText.Contains('float ds=d*scale;') -eq $expectsHoist) 'Scale hoist does not match the requested variant.'
                Assert-Condition ($afterText.Contains('float ww=ds*float(int(q|(high<<4u))-32);') -eq $expectsHoist) 'Weight expression does not use the requested scale hoist.'
                Assert-Condition ($afterText.Contains('float d=unpackHalf2x16(w[(b+208u)>>2u])[((b+208u)&2u)>>1u];') -eq $expectsHalfLoad) 'Packed half load does not match the requested variant.'
                if ($variant -eq 'skip_unused_batch_rows') {
                    Assert-Condition ($afterText.Contains('if(pc.batch>1u) xs[1][lid]=x[pc.cols+c];')) 'Inactive batch planes are still written.'
                }
                $afterPrefix = $afterText.Substring(0, $afterText.IndexOf('void q6kDot4('))
                $originalPrefix = $sourceText.Substring(0, $sourceText.IndexOf('void q6kDot4('))
                Assert-Condition ($afterPrefix -ceq $originalPrefix) 'Mutation changed Q4 code or shared declarations.'
                $independentSpirv = Join-Path $workspace 'independent.spv'
                $compile = Invoke-FixtureProcess $compiler @('-O', '--target-env=vulkan1.2', '-fshader-stage=compute', $shaderPath, '-o', $independentSpirv)
                Assert-Condition ($compile.exit_code -eq 0) ("Independent compilation failed: " + $compile.stderr)
                $validate = Invoke-FixtureProcess $validator @('--target-env', 'vulkan1.2', $spirvPath)
                Assert-Condition ($validate.exit_code -eq 0) ("Variant validation failed: " + $validate.stderr)
                $spirvHash = (Get-FileHash -LiteralPath $spirvPath).Hash
                Assert-Condition ($spirvHash -ceq (Get-FileHash -LiteralPath $independentSpirv).Hash) 'SPIR-V is stale or was compiled from different source.'
                $entry.source_sha256 = (Get-FileHash -LiteralPath $shaderPath).Hash
                $entry.spirv_sha256 = $spirvHash
                $entry.spirv_changed = $spirvHash -cne $baselineSpirvHash
                $replay = Invoke-FixtureProcess $pwsh @('-NoProfile', '-File', $mutationPath) $environmentOverrides
                Assert-Condition ($replay.exit_code -ne 0) 'An already applied variant was accepted again.'
                Assert-Condition ((Get-FileHash -LiteralPath $shaderPath).Hash -ceq $entry.source_sha256) 'Rejected replay changed the source.'
                Assert-Condition ((Get-FileHash -LiteralPath $spirvPath).Hash -ceq $spirvHash) 'Rejected replay changed the compiled shader.'
                $entry.replay_rejected = $true
            }
            $entry.pass = $true
        } catch { $entry.failure = $_.Exception.Message }
        [void]$results.Add([pscustomobject]$entry)
        Write-Output ("CASE={0} PASS={1}" -f $entry.name, $entry.pass)
    }
    $halfWordEntry = [ordered]@{ name = 'half_word_boundaries'; pass = $false; patterns_checked = 0; block_counts_checked = 0 }
    try {
        $packed = [byte[]]::new(4)
        foreach ($halfIndex in @(0, 1)) {
            for ($halfBits = 0; $halfBits -le 65535; $halfBits++) {
                $packed[0] = 90; $packed[1] = 165; $packed[2] = 60; $packed[3] = 195
                $packed[$halfIndex * 2] = [byte]($halfBits -band 255)
                $packed[$halfIndex * 2 + 1] = [byte]($halfBits -shr 8)
                $word = [BitConverter]::ToUInt32($packed, 0)
                $selected = [uint16](($word -shr ($halfIndex * 16)) -band 65535)
                $reference = [BitConverter]::ToUInt16($packed, $halfIndex * 2)
                Assert-Condition ($selected -eq $reference) 'Aligned half extraction selected different bits from the byte reference.'
                $halfWordEntry.patterns_checked++
            }
        }
        for ($blockCount = 1; $blockCount -le 128; $blockCount++) {
            $scaleByte = ($blockCount - 1) * 210 + 208
            $paddedBytes = ($blockCount * 210 + 3) -band -4
            $lastLoadedByte = ($scaleByte -band -4) + 3
            Assert-Condition ($lastLoadedByte -lt $paddedBytes) 'Scale word load crosses the final padded Q6 buffer boundary.'
            $halfWordEntry.block_counts_checked++
        }
        $halfWordEntry.pass = $true
    } catch { $halfWordEntry.failure = $_.Exception.Message }
    [void]$results.Add([pscustomobject]$halfWordEntry)
    Write-Output ("CASE={0} PASS={1}" -f $halfWordEntry.name, $halfWordEntry.pass)
    $workspacePreserved = (Get-FileHash -LiteralPath $sourceShader).Hash -ceq $sourceHash -and (Get-FileHash -LiteralPath $sourceSpirv).Hash -ceq $sourceSpirvHash
    $passed = @($results | Where-Object { -not $_.pass }).Count -eq 0 -and $workspacePreserved
    $report = [ordered]@{
        schema = 'RAWRXD_Q6_MUTATION_SOURCE_CERT_001'
        generated_utc = [DateTime]::UtcNow.ToString('o')
        passed = $passed
        benchmarks_launched = 0
        mutation_script_sha256 = (Get-FileHash -LiteralPath $mutationPath).Hash
        accepted_source_sha256 = $sourceHash
        accepted_spirv_sha256 = $sourceSpirvHash
        compiled_baseline_spirv_sha256 = $baselineSpirvHash
        source_workspace_preserved = $workspacePreserved
        test_count = $results.Count
        results = @($results)
    }
    if ($ReportPath) {
        $reportDestination = [IO.Path]::GetFullPath($ReportPath)
        New-Item -ItemType Directory -Path (Split-Path -Parent $reportDestination) -Force | Out-Null
        [IO.File]::WriteAllText($reportDestination, ($report | ConvertTo-Json -Depth 8), $utf8)
        Write-Output "REPORT=$reportDestination"
    }
    Write-Output ("SOURCE_CERT_PASS={0} CASES={1} SOURCE_PRESERVED={2}" -f $passed, $results.Count, $workspacePreserved)
    if (-not $passed) { exit 1 }
} finally {
    $fullFixture = [IO.Path]::GetFullPath($fixtureRoot)
    $tempPrefix = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\') + '\'
    if (-not $fullFixture.StartsWith($tempPrefix, [StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($fullFixture) -notlike 'rawrxd_q6_mutation_tests_*') { throw 'Refusing fixture cleanup outside the owned temp directory.' }
    if (Test-Path -LiteralPath $fullFixture) { Remove-Item -LiteralPath $fullFixture -Recurse -Force }
}
