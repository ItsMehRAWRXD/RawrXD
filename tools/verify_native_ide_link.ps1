# Native Windows linker certification. PowerShell 5.1 compatible.
# Never report success when the IDE target is absent or an unresolved external occurs.
param(
    [string]$BuildDir = "build-native-link-cert",
    [string]$Generator = "Visual Studio 17 2022",
    [string]$Configuration = "Release",
    [switch]$CleanBuild,
    [switch]$RunReapTests
)
$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$buildPath = if ([IO.Path]::IsPathRooted($BuildDir)) { $BuildDir } else { Join-Path $root $BuildDir }
if ($CleanBuild -and (Test-Path -LiteralPath $buildPath)) {
    Remove-Item -LiteralPath $buildPath -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $buildPath | Out-Null
$logPath = Join-Path $buildPath "native-ide-link-certification.log"
$log = New-Object 'System.Collections.Generic.List[string]'
function Invoke-CertCommand([string[]]$Arguments) {
    # Native compiler diagnostics may be written to stderr even on success.
    # Capture both streams without treating a warning as a PowerShell exception.
    $previousPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { $output = & cmake @Arguments 2>&1; $exit = $LASTEXITCODE }
    finally { $ErrorActionPreference = $previousPreference }
    foreach ($line in $output) {
        $text = [string]$line
        $script:log.Add($text)
        Write-Host $text
    }
    if ($exit -ne 0) { throw "cmake exited $exit (arguments: $($Arguments -join ' '))" }
}
$certified = $false
try {
    Invoke-CertCommand -Arguments @("-S", $root, "-B", $buildPath, "-G", $Generator,
        "-A", "x64", "-DRAWRXD_REQUIRE_NATIVE_IDE_LINK=ON")
    Invoke-CertCommand -Arguments @("--build", $buildPath, "--config", $Configuration,
        "--target", "RawrXD-Win32IDE-Native", "--parallel", "2")
    # A successful command is not enough: verify the executable was produced.
    $exeCandidates = @(
        (Join-Path $buildPath "bin\$Configuration\RawrXD-Win32IDE-Native.exe"),
        (Join-Path $buildPath "$Configuration\RawrXD-Win32IDE-Native.exe"),
        (Join-Path $buildPath "bin\RawrXD-Win32IDE-Native.exe")
    )
    $executable = @($exeCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1)
    if ($executable.Count -eq 0) { throw "Native IDE executable missing after successful build" }
    $script:log.Add("NATIVE_IDE_EXECUTABLE=$($executable[0])")
    $script:log.Add("NATIVE_IDE_SHA256=$((Get-FileHash -LiteralPath $executable[0] -Algorithm SHA256).Hash)")
    if ($RunReapTests) {
        Invoke-CertCommand -Arguments @("--build", $buildPath, "--config", $Configuration,
            "--target", "reap_msvc_link_contract_test", "reap_msvc_anchor_only_test",
            "reap_virtual_payload_msvc_adaptive_test", "--parallel", "2")
        $previousPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            $ctestOutput = & ctest --test-dir $buildPath -C $Configuration --output-on-failure --no-tests=error -R "^reap_(msvc_link_contract_test|msvc_anchor_only_test|virtual_payload_msvc_adaptive_test)$" 2>&1
            $ctestExit = $LASTEXITCODE
        }
        finally { $ErrorActionPreference = $previousPreference }
        foreach ($line in $ctestOutput) {
            $text = [string]$line
            $script:log.Add($text)
            Write-Host $text
        }
        if ($ctestExit -ne 0) { throw "REAP native linker acceptance tests failed with exit $ctestExit" }
    }
    $certified = $true
}
catch {
    $log.Add("CERTIFICATION_FAILED: $($_.Exception.Message)")
    Write-Host "CERTIFICATION_FAILED: $($_.Exception.Message)"
}
finally {
    # Always extract unresolved externals, including when the build exits nonzero.
    # The previous success-only check never reached this code on LNK2019.
    $unresolved = @($log | Where-Object {
        $_ -match 'LNK(?:2001|2019|1120)\b|unresolved external symbol'
    })
    $log.Add("UNRESOLVED_EXTERNAL_DIAGNOSTICS=$($unresolved.Count)")
    foreach ($diagnostic in $unresolved) {
        $log.Add("UNRESOLVED_EXTERNAL: $diagnostic")
    }
    if ($unresolved.Count -gt 0) { $certified = $false }
    $log.Add("NATIVE_IDE_LINK_CERTIFIED=$([int]$certified)")
    [IO.File]::WriteAllLines($logPath, [string[]]$log)
    Write-Host "Evidence: $logPath"
}
if (-not $certified) { exit 1 }
exit 0
