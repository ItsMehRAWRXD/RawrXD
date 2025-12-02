@echo off
setlocal
set "PATH=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer;%PATH%"
for /f "tokens=*" %%i in ('vswhere -latest -property installationPath') do call "%%i\VC\Auxiliary\Build\vcvars64.bat" >nul
ml64 /nologo /Fe:model-llm-harvester.exe model-llm-harvester.asm /link /subsystem:console /entry:main
endlocal
