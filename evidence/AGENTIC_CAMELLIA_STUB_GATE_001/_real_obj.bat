@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "g:\~dev\rawrxd\evidence\AGENTIC_CAMELLIA_STUB_GATE_001"
cl /nologo /c /EHsc /O2 /DRAWR_HAS_MASM=1 /DWIN32 /D_WINDOWS /DNOMINMAX /DWIN32_LEAN_AND_MEAN /D_CRT_SECURE_NO_WARNINGS -std:c++latest /W0 /I"g:\~dev\rawrxd\include" /I"g:\~dev\rawrxd\src" /I"g:\~dev\rawrxd\src\win32app" /I"g:\~dev\rawrxd\src\core" /I"g:\~dev\rawrxd\src\ide" /I"g:\~dev\rawrxd\src\agent" /I"g:\~dev\rawrxd\src\agentic" /I"g:\~dev\rawrxd\Ship" /FoWin32IDE_AgenticFeatures_masm1.obj "g:\~dev\rawrxd\src\win32app\Win32IDE_AgenticFeatures.cpp" > cl_real_masm1.log 2>&1
if exist Win32IDE_AgenticFeatures_masm1.obj dumpbin /SYMBOLS Win32IDE_AgenticFeatures_masm1.obj > dumpbin_AgenticFeatures_masm1.txt
