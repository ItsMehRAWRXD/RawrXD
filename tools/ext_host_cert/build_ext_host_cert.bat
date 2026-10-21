@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=amd64 -host_arch=amd64 >nul
cd /d F:\RawrXD
set OBJ=C:\Users\Garrett\AppData\Local\Temp\kilo\extobj
if not exist "%OBJ%" mkdir "%OBJ%"
set INC=/I src /I src\core /I src\modules /I include /I 3rdparty\quickjs_ng
set CFLAGS=/nologo /std:c++20 /EHsc /c /W3 /permissive- /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS %INC%

echo === compiling extension runtime from tracked source ===
cl %CFLAGS% src\core\js_extension_host.cpp /Fo:%OBJ%\js_extension_host.obj || goto :fail
cl %CFLAGS% src\core\extension_polyfill_engine.cpp /Fo:%OBJ%\extension_polyfill_engine.obj || goto :fail
cl %CFLAGS% src\marketplace\vsix_installer.cpp /Fo:%OBJ%\vsix_installer.obj || goto :fail
cl %CFLAGS% src\core\zip_reader.cpp /Fo:%OBJ%\zip_reader.obj || goto :fail
cl %CFLAGS% src\modules\vscode_extension_api.cpp /Fo:%OBJ%\vscode_extension_api.obj || goto :fail
cl %CFLAGS% tools\ext_host_cert\ext_host_cert.cpp /Fo:%OBJ%\ext_host_cert.obj || goto :fail

echo === compiling the vendored QuickJS runtime from tracked source ===
rem quickjs-ng needs C11 atomics.
set CFLAGS11=/nologo /std:c11 /EHsc /c /W3 /permissive- /DNOMINMAX /D_CRT_SECURE_NO_WARNINGS %INC%
cl %CFLAGS11% 3rdparty\quickjs_ng\quickjs.c /Fo:%OBJ%\quickjs.obj || goto :fail
cl %CFLAGS11% 3rdparty\quickjs_ng\libregexp.c /Fo:%OBJ%\libregexp.obj || goto :fail
cl %CFLAGS11% 3rdparty\quickjs_ng\libunicode.c /Fo:%OBJ%\libunicode.obj || goto :fail
cl %CFLAGS11% 3rdparty\quickjs_ng\dtoa.c /Fo:%OBJ%\dtoa.obj || goto :fail

echo === linking ===
cd /d %OBJ%
link /nologo /OUT:ext_host_cert.exe ext_host_cert.obj js_extension_host.obj extension_polyfill_engine.obj vsix_installer.obj zip_reader.obj vscode_extension_api.obj quickjs.obj libregexp.obj libunicode.obj dtoa.obj user32.lib shell32.lib advapi32.lib wintrust.lib shlwapi.lib crypt32.lib comdlg32.lib
if errorlevel 1 goto :fail
echo === BUILD OK ===
exit /b 0
:fail
echo === BUILD FAILED ===
exit /b 1

