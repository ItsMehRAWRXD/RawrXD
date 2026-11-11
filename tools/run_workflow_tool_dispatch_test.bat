@echo off
REM ============================================================================
REM Acceptance test for the Qt-free, dependency-free rawrxd_workflow library.
REM
REM Exercises all 11 workflow tools (browser_* + github_*) through
REM RawrXD::Workflow::dispatchWorkflowTool -- the exact entry point that
REM AgenticExecutor::callTool delegates to.
REM
REM Browser tools run against a LIVE WebView2. Every asserted value is
REM derived at runtime from a per-run unique token written into the DOM,
REM so a stubbed or hardcoded return value cannot satisfy the checks.
REM
REM Deliberately Qt-free: only the Windows SDK, winhttp, and the vendored
REM WebView2Loader are linked (matches src/workflow/CMakeLists.txt).
REM ============================================================================
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
if "%INCLUDE%"=="" (
    echo ERROR: vcvarsall failed to initialize the MSVC environment.
    exit /b 1
)

set INCLUDE=F:\rawrxd\include;%INCLUDE%

cl /nologo /EHsc /std:c++17 /Zc:__cplusplus /permissive- /bigobj ^
   /I F:\rawrxd /I F:\rawrxd\src /I F:\rawrxd\include ^
   /I F:\rawrxd\src\browser /I F:\rawrxd\src\github ^
   /DNOMINMAX /D_WIN32_WINNT=0x0A00 /D_CRT_SECURE_NO_WARNINGS ^
   F:\rawrxd\tools\workflow_tool_dispatch_test.cpp ^
   F:\rawrxd\src\agentic_workflow_bridge.cpp ^
   F:\rawrxd\src\browser\BrowserTestEngine.cpp ^
   F:\rawrxd\src\github\GitHubIntegration.cpp ^
   /Fe%TEMP%\workflow_tool_dispatch_test.exe ^
   /link winhttp.lib user32.lib bcrypt.lib ole32.lib oleaut32.lib
if errorlevel 1 (
    echo BUILD_FAILED
    exit /b 1
)

%TEMP%\workflow_tool_dispatch_test.exe
set RUN_EXIT=%ERRORLEVEL%
echo RUN_EXIT=%RUN_EXIT%
exit /b %RUN_EXIT%
