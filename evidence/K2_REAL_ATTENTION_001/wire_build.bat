call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d G:\~dev\rawrxd
if not exist "G:\~dev\rawrxd\evidence\K2_REAL_ATTENTION_001\RawrXD_K2_RealAttention_x64.obj" (
  call "G:\~dev\rawrxd\evidence\K2_REAL_ATTENTION_001\build_run.bat"
)
cl /nologo /EHsc /std:c++17 /O2 /I. /Isrc /Fo"G:\~dev\rawrxd\evidence\K2_REAL_ATTENTION_001\\" /Fe"G:\~dev\rawrxd\evidence\K2_REAL_ATTENTION_001\k2_xr_wire_001.exe" "G:\~dev\rawrxd\evidence\K2_REAL_ATTENTION_001\k2_xr_wire_001.cpp" /link "G:\~dev\rawrxd\evidence\K2_REAL_ATTENTION_001\RawrXD_K2_RealAttention_x64.obj"
echo CL_EXIT=%ERRORLEVEL%
"G:\~dev\rawrxd\evidence\K2_REAL_ATTENTION_001\k2_xr_wire_001.exe"
echo RUN_EXIT=%ERRORLEVEL%
