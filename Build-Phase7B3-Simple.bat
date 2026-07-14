@echo off
setlocal

set "VS_ROOT=C:\Program Files\Microsoft Visual Studio\18\Enterprise"
set "VC_TOOLS=%VS_ROOT%\VC\Tools\MSVC\14.51.36231"
set "WINSDK_ROOT=C:\Program Files (x86)\Windows Kits\10"
set "WINSDK_VER=10.0.22621.0"

set "PATH=%VC_TOOLS%\bin\Hostx64\x64;%PATH%"
set "INCLUDE=%VC_TOOLS%\include;%WINSDK_ROOT%\Include\%WINSDK_VER%\ucrt;%WINSDK_ROOT%\Include\%WINSDK_VER%\um;%WINSDK_ROOT%\Include\%WINSDK_VER%\shared"
set "LIB=%VC_TOOLS%\lib\x64;%WINSDK_ROOT%\Lib\%WINSDK_VER%\ucrt\x64;%WINSDK_ROOT%\Lib\%WINSDK_VER%\um\x64"

if not exist build_phase7b3_autonomous mkdir build_phase7b3_autonomous

echo Compiling Phase 7B.3...
cl.exe /O2 /EHsc /std:c++17 /arch:AVX2 /fp:fast /MD ^
    RawRamXD_Phase7B3_AutonomousPlacement.cpp ^
    RawRamXD_Phase7B3_AutonomousTest.cpp ^
    kernel32.lib user32.lib ^
    /Fe:build_phase7b3_autonomous\RawRamXD_Phase7B3_Autonomous.exe ^
    /Fo:build_phase7b3_autonomous\ ^
    /link /SUBSYSTEM:CONSOLE /OPT:REF /OPT:ICF

if %ERRORLEVEL% neq 0 (
    echo Build failed!
    exit /b 1
)

echo Build successful!
echo Running tests...
cd build_phase7b3_autonomous
RawRamXD_Phase7B3_Autonomous.exe
cd ..
