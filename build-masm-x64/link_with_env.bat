@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvars64.bat"
cd /d "d:\rawrxd\build-masm-x64"
link @link_response.txt /OUT:RawrXD_x64_IDE.exe /SUBSYSTEM:WINDOWS /ENTRY:WinMainCRTStartup /LARGEADDRESSAWARE /MACHINE:X64 /DEBUG:FULL /OPT:REF /OPT:ICF kernel32.lib user32.lib gdi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib advapi32.lib ws2_32.lib winmm.lib comdlg32.lib comctl32.lib shlwapi.lib msimg32.lib version.lib imm32.lib dwmapi.lib uxtheme.lib > link_output.log 2>&1
echo Link complete with exit code: %ERRORLEVEL%
pause
