@echo off
setlocal

REM Set up MSVC environment manually
set "VCINSTALLDIR=C:\Program Files\Microsoft Visual Studio\18\Enterprise\VC"
set "VCToolsVersion=14.51.36231"
set "VCToolsInstallDir=%VCINSTALLDIR%\Tools\MSVC\%VCToolsVersion%"
set "WindowsSdkDir=C:\Program Files (x86)\Windows Kits\10"
set "WindowsSdkVersion=10.0.22621.0"

set "PATH=%VCToolsInstallDir%\bin\HostX64\x64;%PATH%"
set "LIB=%VCToolsInstallDir%\lib\x64;%WindowsSdkDir%\Lib\%WindowsSdkVersion%\ucrt\x64;%WindowsSdkDir%\Lib\%WindowsSdkVersion%\um\x64"
set "INCLUDE=%VCToolsInstallDir%\include;%WindowsSdkDir%\Include\%WindowsSdkVersion%\ucrt;%WindowsSdkDir%\Include\%WindowsSdkVersion%\um;%WindowsSdkDir%\Include\%WindowsSdkVersion%\shared"

cd /d d:\rawrxd\build
ninja rawrxd
