$ErrorActionPreference = 'Stop'
$cl = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe'
$vcvars = 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat'

# Set up environment by running vcvarsall and capturing env
$tempBatch = 'F:\rawrxd\tmp_build.bat'
@"
call "$vcvars" x64 >nul 2>&1
"$cl" /std:c++17 /EHsc /I "F:\rawrxd\include" "F:\rawrxd\tmp_json_test.cpp" /Fe:"F:\rawrxd\tmp_json_test.exe" /nologo
"@ | Set-Content -LiteralPath $tempBatch -Encoding ASCII

cmd.exe /c $tempBatch
