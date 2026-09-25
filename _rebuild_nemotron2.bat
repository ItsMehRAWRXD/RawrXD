@echo off
setlocal enabledelayedexpansion

:: Set up MSVC x64 environment
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"

set "BUILD=f:\~dev\rawrxd\build"
set "SRC=f:\~dev\rawrxd\src\deep2"
set "OUT=%BUILD%\bin\Release"

if not exist "%OUT%" mkdir "%OUT%"

set "RESPONSE=%BUILD%\_link_resp.txt"
> "%RESPONSE%" echo.

:: Add all InferenceEngine objects (new Deep2Engine_new.obj instead of old)
for /f "usebackq delims=" %%i in ("F:\~dev\_obj_list.txt") do (
    >>"%RESPONSE%" echo "%%i"
)

:: Add test_generate_313_tokens object
>>"%RESPONSE%" echo "%BUILD%\test_generate_313_tokens.dir\Release\test_generate_313_tokens.obj"

:: Add extra deep2 objects
>>"%RESPONSE%" echo "%SRC%\ResidencyTrace.obj"
>>"%RESPONSE%" echo "%SRC%\QuantKB.obj"

echo --- Linking test_generate_313_tokens.exe with all objects ---
link.exe /nologo /MACHINE:X64 /OUT:"%OUT%\test_generate_313_tokens.exe" @"%RESPONSE%" "C:\VulkanSDK\1.4.357.0\Lib\vulkan-1.lib" shlwapi.lib psapi.lib dbghelp.lib winhttp.lib bcrypt.lib advapi32.lib crypt32.lib dxgi.lib pdh.lib kernel32.lib user32.lib gdi32.lib winspool.lib shell32.lib ole32.lib oleaut32.lib uuid.lib comdlg32.lib

if errorlevel 1 (
    echo FAILED: link
    exit /b 1
)

echo BUILD_OK
echo Output: %OUT%\test_generate_313_tokens.exe
