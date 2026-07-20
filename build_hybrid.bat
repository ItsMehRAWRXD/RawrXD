@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd

"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\ml64.exe" /c /Foobj\quantized_matmul_hybrid.obj /W3 /Zi /Zd /Cp /nologo src\kernels\quantized_matmul_hybrid.asm
if errorlevel 1 goto :error

"C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\lib.exe" /OUT:lib\RawrXD_Hybrid.lib /NOLOGO /MACHINE:X64 obj\quantized_matmul_hybrid.obj lib\RawrXD_QuantizedKernels.lib
if errorlevel 1 goto :error

echo Hybrid library built successfully!
goto :end

:error
echo Build failed!
exit /b 1

:end
