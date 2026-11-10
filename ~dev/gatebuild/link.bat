@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat" -arch=x64 -no_logo < nul
set VK=C:\VulkanSDK\1.4.357.0
del /q F:\rawrxd\~dev\gatebuild\link_err.log 2>nul
link /nologo /OUT:%OUTFILE% F:\rawrxd\~dev\%OBJPATTERN%\*.obj /LIBPATH:"%VK%\Lib" vulkan-1.lib psapi.lib dbghelp.lib winhttp.lib bcrypt.lib advapi32.lib crypt32.lib dxgi.lib pdh.lib shlwapi.lib kernel32.lib user32.lib gdi32.lib ole32.lib oleaut32.lib uuid.lib shell32.lib 2>&1 | findstr /R "LNK1 LNK4 LNK1120 LNK1169 LNK1104" > F:\rawrxd\~dev\gatebuild\link_err.log
if exist F:\rawrxd\~dev\gatebuild\link_err.log type F:\rawrxd\~dev\gatebuild\link_err.log
