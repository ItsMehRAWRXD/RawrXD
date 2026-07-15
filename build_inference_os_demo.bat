@echo off
REM Build script for Inference OS Demo
REM Demonstrates the complete architecture compiles and links

echo Building Self-Observing Inference OS Kernel Demo...
echo.

REM Set up Visual Studio environment
set VS_PATH=C:\Program Files\Microsoft Visual Studio\18\Enterprise
set VC_PATH=%VS_PATH%\VC\Tools\MSVC\14.51.36231
set WINSDK_PATH=C:\Program Files (x86)\Windows Kits\10
set WINSDK_VER=10.0.22621.0
set PATH=%VC_PATH%\bin\Hostx64\x64;%PATH%
set INCLUDE=%VC_PATH%\include;%WINSDK_PATH%\Include\%WINSDK_VER%\ucrt;%WINSDK_PATH%\Include\%WINSDK_VER%\um;%WINSDK_PATH%\Include\%WINSDK_VER%\shared;%INCLUDE%
set LIB=%VC_PATH%\lib\x64;%WINSDK_PATH%\Lib\%WINSDK_VER%\ucrt\x64;%WINSDK_PATH%\Lib\%WINSDK_VER%\um\x64;%LIB%

set SRC_DIR=d:\rawrxd\src
set BUILD_DIR=d:\rawrxd\build-demo
set INCLUDE_DIR=d:\rawrxd\include

REM Create build directory
if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

echo Building standalone demo...
cl /EHsc /std:c++20 /O2 /W3 /nologo "%SRC_DIR%\inference_os_demo_standalone.cpp" /Fe:"%BUILD_DIR%\inference_os_demo.exe"
if errorlevel 1 goto error

echo.
echo ============================================
echo Build successful!
echo.
echo Executable: %BUILD_DIR%\inference_os_demo.exe
echo.
echo Run with: %BUILD_DIR%\inference_os_demo.exe
echo ============================================
goto end

:error
echo.
echo ============================================
echo Build failed!
echo ============================================
exit /b 1

:end

REM Compile core architecture files
cl /c /nologo /W4 /EHsc /O2 /std:c++20 /I%INCLUDE_DIR% /I%SRC_DIR% /Fo%BUILD_DIR%\execution_capability.obj %SRC_DIR%\execution_capability.cpp
if errorlevel 1 goto error

cl /c /nologo /W4 /EHsc /O2 /std:c++20 /I%INCLUDE_DIR% /I%SRC_DIR% /Fo%BUILD_DIR%\execution_policy.obj %SRC_DIR%\execution_policy.cpp
if errorlevel 1 goto error

cl /c /nologo /W4 /EHsc /O2 /std:c++20 /I%INCLUDE_DIR% /I%SRC_DIR% /Fo%BUILD_DIR%\execution_plan.obj %SRC_DIR%\execution_plan.cpp
if errorlevel 1 goto error

cl /c /nologo /W4 /EHsc /O2 /std:c++20 /I%INCLUDE_DIR% /I%SRC_DIR% /Fo%BUILD_DIR%\inference_gateway.obj %SRC_DIR%\inference_gateway.cpp
if errorlevel 1 goto error

cl /c /nologo /W4 /EHsc /O2 /std:c++20 /I%INCLUDE_DIR% /I%SRC_DIR% /Fo%BUILD_DIR%\token_authority.obj %SRC_DIR%\token_authority.cpp
if errorlevel 1 goto error

cl /c /nologo /W4 /EHsc /O2 /std:c++20 /I%INCLUDE_DIR% /I%SRC_DIR% /Fo%BUILD_DIR%\token_lineage.obj %SRC_DIR%\token_lineage.cpp
if errorlevel 1 goto error

cl /c /nologo /W4 /EHsc /O2 /std:c++20 /I%INCLUDE_DIR% /I%SRC_DIR% /Fo%BUILD_DIR%\execution_graph_hash.obj %SRC_DIR%\execution_graph_hash.cpp
if errorlevel 1 goto error

cl /c /nologo /W4 /EHsc /O2 /std:c++20 /I%INCLUDE_DIR% /I%SRC_DIR% /Fo%BUILD_DIR%\statistical_collapse.obj %SRC_DIR%\statistical_collapse.cpp
if errorlevel 1 goto error

cl /c /nologo /W4 /EHsc /O2 /std:c++20 /I%INCLUDE_DIR% /I%SRC_DIR% /Fo%BUILD_DIR%\execution_query_api.obj %SRC_DIR%\execution_query_api.cpp
if errorlevel 1 goto error

cl /c /nologo /W4 /EHsc /O2 /std:c++20 /I%INCLUDE_DIR% /I%SRC_DIR% /Fo%BUILD_DIR%\inference_os_demo.obj %SRC_DIR%\inference_os_demo.cpp
if errorlevel 1 goto error

echo.
echo Linking demo executable...

link /nologo /OUT:%BUILD_DIR%\inference_os_demo.exe ^
    %BUILD_DIR%\execution_capability.obj ^
    %BUILD_DIR%\execution_policy.obj ^
    %BUILD_DIR%\execution_plan.obj ^
    %BUILD_DIR%\inference_gateway.obj ^
    %BUILD_DIR%\token_authority.obj ^
    %BUILD_DIR%\token_lineage.obj ^
    %BUILD_DIR%\execution_graph_hash.obj ^
    %BUILD_DIR%\statistical_collapse.obj ^
    %BUILD_DIR%\execution_query_api.obj ^
    %BUILD_DIR%\inference_os_demo.obj

if errorlevel 1 goto error

echo.
echo ============================================
echo Build successful!
echo.
echo Executable: %BUILD_DIR%\inference_os_demo.exe
echo.
echo Run with: %BUILD_DIR%\inference_os_demo.exe
echo ============================================
goto end

:error
echo.
echo ============================================
echo Build failed!
echo ============================================
exit /b 1

:end
