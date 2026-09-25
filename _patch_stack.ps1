$editbin = (Get-ChildItem -Path 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC' -Filter 'editbin.exe' -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
if ([string]::IsNullOrEmpty($editbin)) { Write-Host 'EDITBIN_NOT_FOUND'; exit 1 }
Write-Host ('editbin=' + $editbin)
$exe = 'f:\~dev\rawrxd\win32ide_strict\build_v4\Release\RawrXD-Win32IDE.exe'
Copy-Item $exe ($exe + '.bak') -Force
& $editbin /STACK:8388608 $exe
Write-Host 'EDITBIN_DONE'
