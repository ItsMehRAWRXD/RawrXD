@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd

"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe" /O2 /arch:AVX512 /EHsc /Fe:test_hybrid.exe src\kernels\test_hybrid_kernel.cpp /link /LIBPATH:lib RawrXD_Hybrid.lib /MACHINE:X64
if errorlevel 1 goto :error

echo Test built successfully!
goto :end

:error
echo Build failed!
exit /b 1

:end