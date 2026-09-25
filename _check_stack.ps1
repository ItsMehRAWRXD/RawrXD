$exe = 'f:\~dev\rawrxd\win32ide_strict\build_v4\Release\RawrXD-Win32IDE.exe'
$dumpbin = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.43.34808\bin\Hostx64\x64\dumpbin.exe'
if (!(Test-Path $dumpbin)) {
    $found = Get-ChildItem -Path 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC' -Filter 'dumpbin.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { $dumpbin = $found.FullName }
}
if (!(Test-Path $dumpbin)) {
    Write-Host 'DUMPBIN_NOT_FOUND'
    exit
}
Write-Host ('dumpbin=' + $dumpbin)
& $dumpbin /HEADERS $exe | Select-String -Pattern 'stack reserve|stack commit' -Context 1
