@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\MSBuild\Current\Bin\MSBuild.exe" "F:\~dev\rawrxd\win32ide_strict\build_v4\RawrXD-Win32IDE.sln" /m /p:Configuration=Release /p:Platform=x64 /t:RawrXD-Win32IDE /verbosity:minimal > "F:\~dev\_build_output.txt" 2>&1
echo BUILD_EXIT_CODE=%ERRORLEVEL%
