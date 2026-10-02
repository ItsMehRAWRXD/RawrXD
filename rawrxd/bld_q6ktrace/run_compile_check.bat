@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
cd /d F:\~dev\rawrxd
if not exist bld_q6ktrace\cchk mkdir bld_q6ktrace\cchk
for %%F in (src\core\dml_asm_impl.cpp src\core\dml_asm_fallback.cpp) do (
  echo ==== %%F
  cl /nologo /c /std:c++17 /EHsc /O2 /W3 /I src /I "C:\VulkanSDK\1.4.357.0\Include" %%F /Fo:bld_q6ktrace\cchk\ 2>&1 | findstr /V "C4267 C4189 C4996"
)
for %%F in (src\core\aperture_q4_0_avx512_intrinsics.cpp src\core\aperture_q8_0_avx512_intrinsics.cpp) do (
  echo ==== %%F
  cl /nologo /c /std:c++17 /EHsc /O2 /W3 /arch:AVX512 /I src %%F /Fo:bld_q6ktrace\cchk\ 2>&1 | findstr /V "C4267 C4189 C4996"
)
echo ==== COMPILE CHECK COMPLETE