@echo off
REM Build gpu_backend.dll

set CL_PATH=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\bin\Hostx64\x64\cl.exe
set VULKAN_SDK=C:\VulkanSDK\1.4.328.1
set WINSDK_INC=C:\Program Files (x86)\Windows Kits\10\Include\10.0.22621.0
set WINSDK_LIB=C:\Program Files (x86)\Windows Kits\10\Lib\10.0.22621.0
set MSVC_INC=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC\Tools\MSVC\14.51.36231\include

"%CL_PATH%" /EHsc /O2 /W3 /nologo ^
    /I"%VULKAN_SDK%\Include" ^
    /I"%MSVC_INC%" ^
    /I"%WINSDK_INC%\um" ^
    /I"%WINSDK_INC%\shared" ^
    /I"%WINSDK_INC%\ucrt" ^
    d:\rawrxd\src\backend\gpu_backend.cpp ^
    /link /DLL /OUT:d:\rawrxd\gpu_backend.dll ^
    /LIBPATH:"%VULKAN_SDK%\Lib" ^
    /LIBPATH:"%WINSDK_LIB%\um\x64" ^
    /LIBPATH:"%WINSDK_LIB%\ucrt\x64" ^
    vulkan-1.lib kernel32.lib

echo.
if %ERRORLEVEL% equ 0 (
    echo Build SUCCESS
    dir d:\rawrxd\gpu_backend.dll
) else (
    echo Build FAILED
)
pause
