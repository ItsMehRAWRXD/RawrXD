@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 >nul
if errorlevel 1 exit /b 1
set "OUT=%~dp0..\..\evidence\IDE_RELEASE_READINESS_001"
cl /nologo /std:c++17 /EHsc /W4 /WX /I"%~dp0..\..\src\win32app" /Fe:"%OUT%\native_profile_path_test.exe" /Fo:"%OUT%\native_profile_path_test.obj" "%~dp0native_profile_path_test.cpp" shell32.lib ole32.lib
if errorlevel 1 exit /b 1
"%OUT%\native_profile_path_test.exe"
exit /b %errorlevel%
