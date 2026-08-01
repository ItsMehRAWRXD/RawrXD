@echo off
setlocal

call "C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
set INCLUDE=%INCLUDE%;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\shared;C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0\um
set LIB=%LIB%;C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0\um\x64

if not exist "d:\rawrxd-ci-bootstrap\build\obj" mkdir "d:\rawrxd-ci-bootstrap\build\obj"
if not exist "d:\rawrxd-ci-bootstrap\build\bin" mkdir "d:\rawrxd-ci-bootstrap\build\bin"

set O=d:\rawrxd-ci-bootstrap\build\obj
set S=d:\rawrxd-ci-bootstrap\src
set I=/I"%S%" /I"%S%\engine" /I"%S%\engine\kernels" /I"%S%\engine\graph" /I"%S%\engine\inference" /I"%S%\storage"

echo === Step 1: Assemble MASM ===
ml64.exe /c /Cx /Fo"%O%\sovereign_q4k_gemv.obj" "d:\rawrxd\src\deep2\sovereign_q4k_gemv.asm"
if errorlevel 1 exit /b 1

echo === Step 2: Compile C++ ===
cl /O2 /EHsc /std:c++17 /c /Fo"%O%\SovereignIDE.obj" "%S%\SovereignIDE.cpp" %I%
if errorlevel 1 exit /b 1
cl /O2 /EHsc /std:c++17 /c /Fo"%O%\GraphBuilder.obj" "%S%\engine\graph\GraphBuilder.cpp" %I%
if errorlevel 1 exit /b 1
cl /O2 /EHsc /std:c++17 /c /Fo"%O%\StreamEngine.obj" "%S%\engine\inference\StreamEngine.cpp" %I%
if errorlevel 1 exit /b 1
cl /O2 /EHsc /std:c++17 /c /Fo"%O%\MemoryMappedModel.obj" "%S%\storage\MemoryMappedModel.cpp" %I%
if errorlevel 1 exit /b 1
cl /O2 /EHsc /std:c++17 /c /Fo"%O%\Gemv_Q4_0.obj" "%S%\engine\kernels\Gemv_Q4_0.cpp" %I%
if errorlevel 1 exit /b 1
cl /O2 /EHsc /std:c++17 /c /Fo"%O%\Dequantize_Q4_0.obj" "%S%\engine\kernels\Dequantize_Q4_0.cpp" %I%
if errorlevel 1 exit /b 1
cl /O2 /EHsc /std:c++17 /c /Fo"%O%\MathOps.obj" "%S%\engine\kernels\MathOps.cpp" %I%
if errorlevel 1 exit /b 1

echo === Step 3: Link ===
link /OUT:"d:\rawrxd-ci-bootstrap\build\bin\SovereignIDE.exe" /SUBSYSTEM:CONSOLE /LTCG /OPT:REF /OPT:ICF ^
    "%O%\SovereignIDE.obj" "%O%\GraphBuilder.obj" "%O%\StreamEngine.obj" "%O%\MemoryMappedModel.obj" ^
    "%O%\Gemv_Q4_0.obj" "%O%\Dequantize_Q4_0.obj" "%O%\MathOps.obj" "%O%\sovereign_q4k_gemv.obj" ^
    user32.lib gdi32.lib comdlg32.lib kernel32.lib advapi32.lib shell32.lib
if errorlevel 1 exit /b 1

echo.
echo === Build Complete ===
dir d:\rawrxd-ci-bootstrap\build\bin\SovereignIDE.exe
