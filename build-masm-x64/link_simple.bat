@echo off
cd /d "d:\rawrxd\build-masm-x64"
echo Starting link process...
echo Object files to link: 
find /c /v "" link_response.txt
"C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\link.exe" @link_response.txt /OUT:RawrXD_x64_IDE.exe /SUBSYSTEM:WINDOWS /ENTRY:WinMainCRTStartup /LARGEADDRESSAWARE /MACHINE:X64 /DEBUG:FULL /OPT:REF /OPT:ICF kernel32.lib user32.lib gdi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib advapi32.lib ws2_32.lib winmm.lib comdlg32.lib comctl32.lib shlwapi.lib msimg32.lib version.lib imm32.lib dwmapi.lib uxtheme.lib > link_output.log 2>&1
if %ERRORLEVEL% == 0 (
    echo SUCCESS: RawrXD_x64_IDE.exe created!
    dir RawrXD_x64_IDE.exe
) else (
    echo FAILED with error code: %ERRORLEVEL%
    type link_output.log
)
