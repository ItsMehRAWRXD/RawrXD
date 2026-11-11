@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 >nul
if errorlevel 1 exit /b 1
cl /nologo /W4 /WX /EHsc /Fe:"%~dp0acceptance.exe" /Fo:"%~dp0acceptance.obj" "%~dp0acceptance.cpp"
if errorlevel 1 exit /b 1
"%~dp0acceptance.exe"
exit /b %errorlevel%
