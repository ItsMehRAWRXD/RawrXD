# Native Windows linker certification. PowerShell 5.1 compatible.
# Never report success when the IDE target is absent or an unresolved external occurs.
param(
    [string]$BuildDir = "build-native-link-cert",
    [string]$Generator = "Visual Studio 17 2022",
    [string]$Configuration = "Release"
)
$ErrorActionPreference = "Stop"
$root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$buildPath = if ([IO.Path]::IsPathRooted($BuildDir)) { $BuildDir } else { Join-Path $root $BuildDir }
New-Item -ItemType Directory -Force -Path $buildPath | Out-Null
$logPath = Join-Path $buildPath "native-ide-link-certification.log"
$log = New-Object 'System.Collections.Generic.List[string]'
function Invoke-CertCommand([string[]]$Arguments) {
    $output = & cmake @Arguments 2>&1
    $exit = $LASTEXITCODE
    foreach ($line in $output) {
        $text = [string]$line
        $script:log.Add($text)
        Write-Host $text
    }
    if ($exit -ne 0) { throw "cmake exited $exit (arguments: $($Arguments -join ' '))" }
}
$certified = $false
try {
    Invoke-CertCommand @("-S", $root, "-B", $buildPath, "-G", $Generator,
        "-A", "x64", "-DRAWRXD_REQUIRE_NATIVE_IDE_LINK=ON")
    Invoke-CertCommand @("--build", $buildPath, "--config", $Configuration,
        "--target", "RawrXD-Win32IDE-Native", "--parallel", "2")
    $unresolved = @($log | Where-Object { $_ -match 'LNK(?:2001|2019|1120)\b|unresolved external symbol' })
    if ($unresolved.Count -gt 0) { throw "Unresolved external(s) found in native IDE build output" }
    $certified = $true
}
catch {
    $log.Add("CERTIFICATION_FAILED: $($_.Exception.Message)")
    Write-Error $_.Exception.Message
}
finally {
    $log.Add("NATIVE_IDE_LINK_CERTIFIED=$([int]$certified)")
    [IO.File]::WriteAllLines($logPath, [string[]]$log)
    Write-Host "Evidence: $logPath"
}
if (-not $certified) { exit 1 }
exit 0
