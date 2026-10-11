@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
cl /std:c++20 /EHsc /O2 /nologo ^
  /I F:\rawrxd\3rdparty\ggml\include ^
  /I F:\rawrxd\3rdparty\ggml\src ^
  /I F:\rawrxd\build_ggml_profiler\src\Release ^
  /FeF:\rawrxd\tools\nemotron_mamba2_parity.exe F:\rawrxd\tools\nemotron_mamba2_parity.cpp ^
  F:\rawrxd\build_ggml_profiler\src\Release\ggml.lib ^
  F:\rawrxd\build_ggml_profiler\src\Release\ggml-base.lib ^
  F:\rawrxd\build_ggml_profiler\src\Release\ggml-cpu.lib
