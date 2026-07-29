@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd

"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe" /O2 /arch:AVX512 /EHsc /Fe:test_hybrid.exe src\kernels\test_hybrid_kernel.cpp /link /LIBPATH:lib /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64" /LIBPATH:"C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\ucrt\x64" RawrXD_Hybrid.lib kernel32.lib /MACHINE:X64
if errorlevel 1 goto :error

echo Test built successfully!
goto :end

:error
echo Build failed!
exit /b 1

:end