@echo off
REM ===========================================================================
REM  build_runtime.cmd — Build RawrXD Runtime Engine
REM  Assembles all MASM x64 files and links runtime_smoke.exe
REM ===========================================================================
setlocal enabledelayedexpansion

set ROOT=D:\rawrxd-ci-bootstrap
set ML64=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\ml64.exe
set LINK=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe
set OBJDIR=%ROOT%\build\obj
set BINDIR=%ROOT%\build\bin
set SRCDIR=%ROOT%\src
set AGENTDIR=%SRCDIR%\agentic
set KERNELDIR=%SRCDIR%\validation\kernels\masm

REM Include paths
set INC=/I"%SRCDIR%" /I"%SRCDIR%\runtime" /I"%SRCDIR%\model" /I"%SRCDIR%\gguf" /I"%SRCDIR%\tokenizer" /I"%SRCDIR%\agent" /I"%SRCDIR%\gpu" /I"%AGENTDIR%" /I"%KERNELDIR%" /I"%ROOT%\tests"

REM SDK
set SDKROOT=C:\Program Files (x86)\Windows Kits\10
set SDKVER_UC=10.0.22621.0
set SDKVER_UM=10.0.26100.0
set MSVCLIB=C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\lib\x64

REM Libs
set BASELIBS=kernel32.lib user32.lib gdi32.lib advapi32.lib shell32.lib shlwapi.lib ucrt.lib

if /i "%1"=="clean" (
    if exist "%OBJDIR%" rmdir /s /q "%OBJDIR%"
    if exist "%BINDIR%" rmdir /s /q "%BINDIR%"
    echo Cleaned.
    exit /b 0
)

if not exist "%OBJDIR%" mkdir "%OBJDIR%"
if not exist "%BINDIR%" mkdir "%BINDIR%"

echo Assembling runtime engine...

set ASMFILES=

REM Runtime files
for %%f in (
    kernel_registry.asm tensor.asm q4_matmul.asm kv_cache.asm
    sampler.asm inference_engine.asm
) do (
    "%ML64%" %INC% /nologo /c /Cx /Zi /Fo"%OBJDIR%\%%~nf.obj" "%SRCDIR%\runtime\%%f" >nul 2>&1
    if errorlevel 1 echo FAILED: %%f & exit /b 1
    set ASMFILES=!ASMFILES! "%OBJDIR%\%%~nf.obj"
)

REM Model
"%ML64%" %INC% /nologo /c /Cx /Zi /Fo"%OBJDIR%\transformer_block.obj" "%SRCDIR%\model\transformer_block.asm" >nul 2>&1
if errorlevel 1 echo FAILED: transformer_block.asm & exit /b 1
set ASMFILES=!ASMFILES! "%OBJDIR%\transformer_block.obj"

REM GGUF
"%ML64%" %INC% /nologo /c /Cx /Zi /Fo"%OBJDIR%\gguf_reader.obj" "%SRCDIR%\gguf\gguf_reader.asm" >nul 2>&1
if errorlevel 1 echo FAILED: gguf_reader.asm & exit /b 1
set ASMFILES=!ASMFILES! "%OBJDIR%\gguf_reader.obj"

REM Tokenizer
"%ML64%" %INC% /nologo /c /Cx /Zi /Fo"%OBJDIR%\bpe.obj" "%SRCDIR%\tokenizer\bpe.asm" >nul 2>&1
if errorlevel 1 echo FAILED: bpe.asm & exit /b 1
set ASMFILES=!ASMFILES! "%OBJDIR%\bpe.obj"

REM Agent
"%ML64%" %INC% /nologo /c /Cx /Zi /Fo"%OBJDIR%\agent_runtime.obj" "%SRCDIR%\agent\agent_runtime.asm" >nul 2>&1
if errorlevel 1 echo FAILED: agent_runtime.asm & exit /b 1
set ASMFILES=!ASMFILES! "%OBJDIR%\agent_runtime.obj"

REM GPU
"%ML64%" %INC% /nologo /c /Cx /Zi /Fo"%OBJDIR%\gpu_backend.obj" "%SRCDIR%\gpu\gpu_backend.asm" >nul 2>&1
if errorlevel 1 echo FAILED: gpu_backend.asm & exit /b 1
set ASMFILES=!ASMFILES! "%OBJDIR%\gpu_backend.obj"

REM Kernel stubs (provide missing symbols)
"%ML64%" %INC% /nologo /c /Cx /Zi /Fo"%OBJDIR%\rmsnorm.obj" "%KERNELDIR%\rmsnorm.asm" >nul 2>&1
if errorlevel 1 echo FAILED: rmsnorm.asm & exit /b 1
set ASMFILES=!ASMFILES! "%OBJDIR%\rmsnorm.obj"

"%ML64%" %INC% /nologo /c /Cx /Zi /Fo"%OBJDIR%\softmax.obj" "%KERNELDIR%\softmax.asm" >nul 2>&1
if errorlevel 1 echo FAILED: softmax.asm & exit /b 1
set ASMFILES=!ASMFILES! "%OBJDIR%\softmax.obj"

"%ML64%" %INC% /nologo /c /Cx /Zi /Fo"%OBJDIR%\silu.obj" "%KERNELDIR%\silu.asm" >nul 2>&1
if errorlevel 1 echo FAILED: silu.asm & exit /b 1
set ASMFILES=!ASMFILES! "%OBJDIR%\silu.obj"

"%ML64%" %INC% /nologo /c /Cx /Zi /Fo"%OBJDIR%\q4_dequant.obj" "%KERNELDIR%\q4_dequant.asm" >nul 2>&1
if errorlevel 1 echo FAILED: q4_dequant.asm & exit /b 1
set ASMFILES=!ASMFILES! "%OBJDIR%\q4_dequant.obj"

REM Smoke test
"%ML64%" %INC% /nologo /c /Cx /Zi /Fo"%OBJDIR%\runtime_smoke.obj" "%ROOT%\tests\runtime_smoke.asm" >nul 2>&1
if errorlevel 1 echo FAILED: runtime_smoke.asm & exit /b 1
set ASMFILES=!ASMFILES! "%OBJDIR%\runtime_smoke.obj"

REM Link
echo Linking runtime_smoke.exe...
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
    exit /b 1
)

for %%f in ("%BINDIR%\*.exe") do echo Built: %%~nxf  %%~zf bytes
echo Done.
exit /b 0
