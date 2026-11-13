@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" || exit /b 1
cd /d G:\~dev\rawrxd\build_ninja || exit /b 1
set CL=
REM compile with dedicated pdb to avoid lock
"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\cl.exe" /nologo /TP /c /EHsc /std:c++latest /MT /O2 /DNDEBUG /DWIN32 /D_WINDOWS /DNOMINMAX /DWIN32_LEAN_AND_MEAN /DRAWR_STANDALONE_INFERENCE=1 /I"G:\~dev\rawrxd\include" /I"G:\~dev\rawrxd\src" /I"G:\~dev\rawrxd\src\deep2" /I"C:\VulkanSDK\1.4.357.0\Include" /FoCMakeFiles\InferenceEngine.dir\src\deep2\Deep2Engine.cpp.obj /FdCMakeFiles\InferenceEngine.dir\Deep2Engine_solo.pdb G:\~dev\rawrxd\src\deep2\Deep2Engine.cpp
echo CL_EXIT=%ERRORLEVEL%
if exist CMakeFiles\InferenceEngine.dir\src\deep2\Deep2Engine.cpp.obj (
  echo OBJ_OK
  dir CMakeFiles\InferenceEngine.dir\src\deep2\Deep2Engine.cpp.obj
) else (
  echo OBJ_MISSING
)
