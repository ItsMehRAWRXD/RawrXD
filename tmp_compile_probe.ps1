$ErrorActionPreference = 'Stop'
$cl = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe'
$vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat'
$src = 'F:\rawrxd\tmp_wv2_probe.cpp'
$exe = 'F:\rawrxd\tmp_wv2_probe.exe'
$tempBatch = 'F:\rawrxd\tmp_build_probe.bat'
@"
call "$vcvars" x64 >nul 2>&1
"$cl" /std:c++17 /EHsc /D NOMINMAX /D _WIN32_WINNT=0x0A00 /wd4530 "$src" /Fe:"$exe" /link user32.lib ole32.lib shlwapi.lib /nologo
"@ | Set-Content -LiteralPath $tempBatch -Encoding ASCII
cmd.exe /c $tempBatch
