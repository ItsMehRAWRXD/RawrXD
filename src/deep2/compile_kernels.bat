@echo off
setlocal

:: Compile Deep2 MoE Kernels for 2K TPS
:: Uses VS2022 Enterprise ml64.exe

call "C:\VS2022Enterprise\VC\Auxiliary\Build\vcvars64.bat"

echo Compiling sovereign_deep2_kernels.asm...
ml64.exe /c /W3 /nologo /Zi /Fo sovereign_deep2_kernels.obj sovereign_deep2_kernels.asm
if %ERRORLEVEL% NEQ 0 (
    echo FAILED: sovereign_deep2_kernels.asm
    exit /b 1
)

echo Compiling sovereign_moe_fused.asm...
ml64.exe /c /W3 /nologo /Zi /Fo sovereign_moe_fused.obj sovereign_moe_fused.asm
if %ERRORLEVEL% NEQ 0 (
    echo FAILED: sovereign_moe_fused.asm
    exit /b 1
)

echo.
echo SUCCESS: All kernels compiled
dir *.obj /b
echo.

endlocal
