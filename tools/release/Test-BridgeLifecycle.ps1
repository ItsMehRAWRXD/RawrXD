#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory = $true)][string]$BuildDirectory,
      [Parameter(Mandatory = $true)][string]$ModelPath,
      [Parameter(Mandatory = $true)][string]$EvidenceDirectory)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ReleaseHash.ps1')
if (Test-Path -LiteralPath $EvidenceDirectory) { throw 'Use a new evidence directory.' }
New-Item -ItemType Directory -Path $EvidenceDirectory | Out-Null
$evidence = (Resolve-Path -LiteralPath $EvidenceDirectory).Path
$build = (Resolve-Path -LiteralPath $BuildDirectory).Path
$cache = Get-Content -LiteralPath (Join-Path $build 'CMakeCache.txt')
$ninjaEntry = $cache | Where-Object { $_ -match '^CMAKE_MAKE_PROGRAM:(FILEPATH|UNINITIALIZED)=' } | Select-Object -First 1
if (-not $ninjaEntry) { throw 'CMAKE_MAKE_PROGRAM is missing from CMakeCache.txt.' }
$ninja = $ninjaEntry.Substring($ninjaEntry.IndexOf('=') + 1)
if (-not (Test-Path -LiteralPath $ninja)) { throw "Configured Ninja executable not found: $ninja" }
$commands = @(& $ninja -C $build -t commands RawrXD-Win32IDE-Native-Ext)
if ($LASTEXITCODE -ne 0) { throw 'Cannot read native target build commands.' }
$compile = $commands | Where-Object { $_ -match ' /Fo\S*Win32IDE_Deep2Bridge.cpp.obj ' } | Select-Object -Last 1
if (-not $compile) { throw 'Cannot identify the product bridge compile command.' }
$object = Join-Path $evidence 'bridge_lifecycle_test.obj'
$source = Join-Path $PSScriptRoot 'bridge_lifecycle_test.cpp'
$compile = $compile -replace ' /Fo\S+', (' /Fo"' + $object + '"')
$compile = $compile -replace ' /Fd\S+', (' /Fd"' + (Join-Path $evidence 'bridge_lifecycle_test.pdb') + '"')
$compile = $compile -replace ' [/-]c .+$', (' /c "' + $source + '"')
if (-not $compile.Contains($source)) { throw 'The test source was not substituted into the compile command.' }
Push-Location -LiteralPath $build
try {
    # Reuse the exact product compile definitions and libraries. This test links
    # the real bridge/engine objects, including the fixed worker lifecycle.
    & cmd.exe /d /c ('call ' + $compile)
    if ($LASTEXITCODE -ne 0) { throw 'Lifecycle test compilation failed.' }
    $linkCommand = $commands | Where-Object { $_ -match 'vs_link_exe.*RawrXD-Win32IDE-Native-Ext.exe' } | Select-Object -Last 1
    if ($linkCommand -notmatch '-- "([^"]*link.exe)" (.+) && cd \."$') { throw 'Cannot identify the product link command.' }
    $link = $Matches[1]; $linkArguments = $Matches[2]
    $testExe = Join-Path $evidence 'bridge_lifecycle_test.exe'
    $linkArguments = $linkArguments -replace '/out:\S+', ('/out:"' + $testExe + '"')
    $linkArguments = $linkArguments -replace '/implib:\S+', ('/implib:"' + (Join-Path $evidence 'bridge_lifecycle_test.lib') + '"')
    $linkArguments = $linkArguments -replace '/pdb:\S+', ('/pdb:"' + (Join-Path $evidence 'bridge_lifecycle_test.pdb') + '"')
    $linkArguments = $linkArguments -replace '/subsystem:windows', '/subsystem:console'
    $linkArguments += ' "' + $object + '" /entry:mainCRTStartup'
    $responseFile = Join-Path $evidence 'link.rsp'
    [IO.File]::WriteAllText($responseFile, $linkArguments)
    & $link ('@' + $responseFile)
    if ($LASTEXITCODE -ne 0) { throw 'Lifecycle test linking failed.' }
    $stdout = Join-Path $evidence 'bridge.stdout.log'
    $stderr = Join-Path $evidence 'bridge.stderr.log'
    $process = Start-Process -FilePath $testExe -ArgumentList ('"' + $ModelPath + '"') `
        -WorkingDirectory $evidence -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    $null = $process.Handle
    $completed = $process.WaitForExit(300000)
    if (-not $completed) { Stop-Process -Id $process.Id -Force; $process.WaitForExit() }
    $process.Refresh()
    $output = [IO.File]::ReadAllText($stdout) + [IO.File]::ReadAllText($stderr)
    $passed = $completed -and $process.ExitCode -eq 0 -and $output -match 'BRIDGE_LIFECYCLE_TEST PASS requests=3'
    $receipt = [ordered]@{tested_utc = [DateTime]::UtcNow.ToString('o');
        status = $(if ($passed) { 'PASS' } else { 'FAIL' }); process_exit = $process.ExitCode;
        timed_out = -not $completed; model = $ModelPath;
        product_ide_sha256 = (Get-FileHash -LiteralPath (Join-Path $build 'bin\RawrXD-Win32IDE-Native-Ext.exe') -Algorithm SHA256).Hash;
        bridge_object_sha256 = (Get-FileHash -LiteralPath (Join-Path $build 'CMakeFiles\RawrXD-Win32IDE-Native-Ext.dir\src\win32app\Win32IDE_Deep2Bridge.cpp.obj') -Algorithm SHA256).Hash;
        test_exe_sha256 = (Get-FileHash -LiteralPath $testExe -Algorithm SHA256).Hash;
        scope = 'Three sequential real-engine generation requests using the product object files.'}
    $receipt | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath (Join-Path $evidence 'bridge-lifecycle.json') -Encoding UTF8
    $receipt
    if (-not $passed) { exit 1 }
} finally { Pop-Location }
