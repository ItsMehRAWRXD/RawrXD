@echo off
setlocal enabledelayedexpansion

set ROOT=D:\rawrxd-ci-bootstrap
set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe
set OBJDIR=%ROOT%\build\obj
set BINDIR=%ROOT%\build\bin
set SRCDIR=%ROOT%\src
set KERNELDIR=%SRCDIR%\validation\kernels\masm

set INC=/I"%SRCDIR%" /I"%SRCDIR%\runtime" /I"%SRCDIR%\model" /I"%SRCDIR%\gguf" /I"%SRCDIR%\tokenizer" /I"%SRCDIR%\agent" /I"%SRCDIR%\gpu" /I"%SRCDIR%\agentic" /I"%KERNELDIR%" /I"%ROOT%\tests"

set SDKROOT=C:\Program Files (x86)\Windows Kits\10
set SDKVER_UC=10.0.22621.0
set SDKVER_UM=10.0.26100.0
set MSVCLIB=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64
set BASELIBS=kernel32.lib user32.lib gdi32.lib advapi32.lib shell32.lib shlwapi.lib ucrt.lib

if /i "%1"=="clean" (
    if exist "%OBJDIR%" rmdir /s /q "%OBJDIR%"
    if exist "%BINDIR%" rmdir /s /q "%BINDIR%"
    echo Cleaned.
    exit /b 0
)

if not exist "%OBJDIR%" mkdir "%OBJDIR%"
if not exist "%BINDIR%" mkdir "%BINDIR%"

echo Assembling...

set ASMFILES=

call :assemble "%SRCDIR%\runtime\kernel_registry.asm" kernel_registry.obj
call :assemble "%SRCDIR%\runtime\tensor.asm" tensor.obj
call :assemble "%SRCDIR%\runtime\q4_matmul.asm" q4_matmul.obj
call :assemble "%SRCDIR%\runtime\kv_cache.asm" kv_cache.obj
call :assemble "%SRCDIR%\runtime\sampler.asm" sampler.obj
call :assemble "%SRCDIR%\runtime\inference_engine.asm" inference_engine.obj
call :assemble "%SRCDIR%\model\transformer_block.asm" transformer_block.obj
call :assemble "%SRCDIR%\gguf\gguf_reader.asm" gguf_reader.obj
call :assemble "%SRCDIR%\tokenizer\bpe.asm" bpe.obj
call :assemble "%SRCDIR%\agent\agent_runtime.asm" agent_runtime.obj
call :assemble "%SRCDIR%\gpu\gpu_backend.asm" gpu_backend.obj
call :assemble "%KERNELDIR%\rmsnorm.asm" rmsnorm.obj
call :assemble "%KERNELDIR%\softmax.asm" softmax.obj
call :assemble "%KERNELDIR%\silu.asm" silu.obj
call :assemble "%KERNELDIR%\q4_dequant.asm" q4_dequant.obj
call :assemble "%ROOT%\tests\runtime_smoke.asm" runtime_smoke.obj

echo Linking...

set RSPFILE=%TEMP%\rawrxd_link.rsp
echo -nologo > "%RSPFILE%"
echo -MACHINE:X64 >> "%RSPFILE%"
echo -OUT:"%BINDIR%\runtime_smoke.exe" >> "%RSPFILE%"
for %%f in (!ASMFILES!) do echo %%f >> "%RSPFILE%"
echo %BASELIBS% >> "%RSPFILE%"
echo /SUBSYSTEM:CONSOLE >> "%RSPFILE%"
echo /ENTRY:WinMain >> "%RSPFILE%"
echo -LIBPATH:"%MSVCLIB%" >> "%RSPFILE%"
echo -LIBPATH:"%SDKROOT%\Lib\%SDKVER_UC%\ucrt\x64" >> "%RSPFILE%"
echo -LIBPATH:"%SDKROOT%\Lib\%SDKVER_UM%\um\x64" >> "%RSPFILE%"

"%LINK%" @"%RSPFILE%"
if errorlevel 1 (
    echo LINK FAILED
    type "%RSPFILE%"
    exit /b 1
)

for %%f in ("%BINDIR%\*.exe") do echo Built: %%~nxf  %%~zf bytes
echo Done.
exit /b 0

:assemble
set SRC=%~1
set OBJ=%2
set OBJPATH=%OBJDIR%\%OBJ%
"%ML64%" %INC% /nologo /c /Cx /Zi /Fo"%OBJPATH%" "%SRC%"
if errorlevel 1 (
    echo FAILED: %OBJ%
    exit /b 1
)
set ASMFILES=!ASMFILES! "%OBJPATH%"
exit /b 0
