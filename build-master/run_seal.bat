@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d d:\rawrxd\build-master

echo === RawrXD Golden Master Sealing ===
echo.

REM Assemble interpreter (without trace collector for now)
echo [1/4] Assembling interpreter.asm...
ml64 /c /W3 /nologo /Zi /Fo:interpreter_seal.obj ..\src\script\masm\interpreter.asm
if errorlevel 1 goto :asm_error

echo [2/4] Compiling golden_master.cpp...
cl /c /std:c++20 /W3 /O2 /nologo /Fo:golden_master.obj ..\src\script\golden_master.cpp /I..\src\script
if errorlevel 1 goto :compile_error

echo [3/4] Compiling seal_full_corpus.cpp...
cl /c /std:c++20 /W3 /O2 /nologo /Fo:seal_corpus.obj ..\src\script\seal_full_corpus.cpp /I..\src\script
if errorlevel 1 goto :compile_error

echo [4/4] Linking...
link /nologo seal_corpus.obj golden_master.obj interpreter_seal.obj /out:seal_corpus.exe /subsystem:console
if errorlevel 1 goto :link_error

echo.
echo === Running Sealing Process ===
seal_corpus.exe
if errorlevel 1 goto :run_error

echo.
echo === Sealing Complete ===
dir rawrxd_golden_masters.* 2>nul
goto :end

:asm_error
echo ERROR: Assembly failed
goto :end

:compile_error
echo ERROR: Compilation failed
goto :end

:link_error
echo ERROR: Linking failed
goto :end

:run_error
echo ERROR: Sealing execution failed
goto :end

:end
