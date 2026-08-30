@echo off
REM GuiRe — x64 MASM source-drop build (user32 + kernel32 only)
setlocal
cd /d "%~dp0"
where ml64 >nul 2>&1
if errorlevel 1 (
  echo ml64 not on PATH — use VS x64 Native Tools Prompt
  exit /b 1
)

ml64 /c /nologo GuiRe_Data.asm || exit /b 1
ml64 /c /nologo GuiRe_Capture.asm || exit /b 1
ml64 /c /nologo GuiRe_WalkUp.asm || exit /b 1
ml64 /c /nologo GuiRe_FromPoint.asm || exit /b 1
ml64 /c /nologo GuiRe_EnumLeaves.asm || exit /b 1
ml64 /c /nologo GuiRe_Edit.asm || exit /b 1
ml64 /c /nologo GuiRe_Dump.asm || exit /b 1
ml64 /c /nologo GuiRe_Menu.asm || exit /b 1
ml64 /c /nologo GuiRe_Entry.asm || exit /b 1

link /nologo /subsystem:console /entry:mainCRTStartup ^
  GuiRe_Data.obj GuiRe_Capture.obj GuiRe_WalkUp.obj GuiRe_FromPoint.obj ^
  GuiRe_EnumLeaves.obj GuiRe_Edit.obj GuiRe_Dump.obj GuiRe_Menu.obj GuiRe_Entry.obj ^
  user32.lib kernel32.lib /out:GuiRe.exe
if errorlevel 1 exit /b 1
echo Built GuiRe.exe — run while RawrXD_IDE_MainWindow is live; writes GuiRe_DUMP.txt
endlocal
