@echo off
setlocal
if not defined VSCMD_ARG_TGT_ARCH (
  echo Run from x64 Native Tools prompt or call vcvars64.bat first.
)
if not exist build mkdir build
cl /nologo /std:c++17 /O2 /EHsc- /GR- /W4 /Iinclude /c src\d2_overlap_core.cpp /Fobuild\d2_overlap_core.obj || exit /b 1
cl /nologo /std:c++17 /O2 /EHsc- /GR- /W4 /Iinclude /c src\d2_material_overlap_win32.cpp /Fobuild\d2_material_overlap_win32.obj || exit /b 1
lib /nologo /OUT:build\d2_material_overlap.lib build\d2_overlap_core.obj build\d2_material_overlap_win32.obj || exit /b 1
cl /nologo /std:c++17 /O2 /EHsc- /GR- /W4 /Iinclude tests\core_selftest.cpp build\d2_overlap_core.obj /Febuild\core_selftest.exe || exit /b 1
build\core_selftest.exe || exit /b 1
echo BUILD=PASS
