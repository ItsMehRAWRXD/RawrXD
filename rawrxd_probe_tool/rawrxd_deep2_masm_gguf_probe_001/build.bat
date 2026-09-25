@echo off
setlocal
where ml64.exe >nul 2>nul || (echo ERROR: ml64.exe not on PATH. Run from a VS x64 Native Tools command prompt.& exit /b 1)
where link.exe >nul 2>nul || (echo ERROR: link.exe not on PATH.& exit /b 1)
ml64.exe /nologo /c /Fo:deep2_probe.obj deep2_probe.asm || exit /b 1
link.exe /nologo /subsystem:console /entry:start /machine:x64 /out:deep2_gguf_probe.exe deep2_probe.obj kernel32.lib || exit /b 1
echo BUILD=PASS
echo EXE=%CD%\deep2_gguf_probe.exe
