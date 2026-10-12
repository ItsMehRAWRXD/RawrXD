# RAW-XD E2E reproduction script (RAWRXD_CORE_DLL_NATIVE_E2E_001)
#
# Reproduces the full certificate from a clean checkout. Requires:
#   - VS2022 BuildTools (cl/cmake), Python 3 with numpy (py -3)
#   - F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf
#   - a built llama.cpp reference at tmp_llama-clone (probe + tokenizer ref)
setlocal
set VSD=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\Tools\VsDevCmd.bat
call "%VSD%" -arch=amd64 -host_arch=amd64 >nul
if errorlevel 1 exit /b 91

set EV=F:\rawrxd\evidence\RAWRXD_CORE_DLL_NATIVE_E2E_001
if not exist "%EV%" mkdir "%EV%"

echo [1/8] standalone IR executor (ggml-parity numerics)
cmd /c F:\rawrxd\_build_mg_baseline.cmd F:\rawrxd\tmp_build_e2e
if errorlevel 1 exit /b 1

echo [2/8] teacher-forced 20-position differential
F:\rawrxd\tmp_build_e2e\rawrxd_modelgenie_ir_executor.exe ^
  F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf "%EV%" ^
  --teacher-forced 1 185 16 15 15 15 15 15 15 15 12 384 2 16 24 207 71955 1392 13 1002 ^
  > "%EV%\teacher_forced_run.log" 2>&1
if errorlevel 1 exit /b 2

echo [3/8] fresh CMake configure + DLL build (Shared)
cmake -S F:\rawrxd -B F:\rawrxd\build_cert -G "Visual Studio 17 2022" -A x64 ^
  -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=ON > "%EV%\cmake_configure2.log" 2>&1
if errorlevel 1 exit /b 3
cmake --build F:\rawrxd\build_cert --config Release --target RawrXDCore -- /m:4 >> "%EV%\cmake_configure2.log" 2>&1
if errorlevel 1 exit /b 3
cmake --build F:\rawrxd\build_cert --config Release --target RawrXDCore_Test -- /m:4 >> "%EV%\cmake_configure2.log" 2>&1
if errorlevel 1 exit /b 3

echo [4/8] DLL lifecycle + 16/64-token generation
F:\rawrxd\build_cert\bin\Release\RawrXDCore_Test.exe > "%EV%\dll_test_run.log" 2>&1
if errorlevel 1 exit /b 4

echo [5/8] E2E evidence capture (per-step authority)
F:\rawrxd\tmp_build_e2e\e2e_evidence.exe F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf "%EV%" ^
  --tokens 1 185 16 > "%EV%\e2e_evidence_run.log" 2>&1
if errorlevel 1 exit /b 5

echo [6/8] llama.cpp reference on the same sequence
set RAWRXD_PROBE_DIR=F:\rawrxd\evidence\RAWRXD_REFERENCE_REPRODUCIBILITY_001\ref_64
if not exist "%RAWRXD_PROBE_DIR%" mkdir "%RAWRXD_PROBE_DIR%"
F:\rawrxd\tmp_build_e2e\rawrxd_kq_probe.exe F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf ^
  64 1 185 16 15 15 15 15 15 15 15 12 384 2 16 24 207 71955 1392 13 1002 6 95 3882 124 2 16 146 24 151 384 37 1827 253 16 24 92 1024 1827 253 16 24 92 12 22 738 30840 4399 4633 15 23 0 626 726 1628 2285 966 6 4 0 82 10 113 4647 1075 2 > nul 2>&1
if errorlevel 1 exit /b 6

echo [7/8] tokenizer reference + parity harness
F:\rawrxd\tmp_build_e2e\rawrxd_tok_ref.exe "%EV%\tokenizer_corpus.txt" "%EV%\tokenizer_reference.bin" > nul 2>&1
if errorlevel 1 exit /b 7
F:\rawrxd\tmp_build_e2e\tokenizer_parity_dll.exe F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf ^
  "%EV%\tokenizer_corpus.txt" "%EV%\tokenizer_reference.bin" "%EV%\tokenizer_parity.json" ^
  > "%EV%\tokenizer_parity_run.log" 2>&1
if errorlevel 1 exit /b 7

echo [8/8] baseline freeze, certificates, independent verification
py -3 F:\rawrxd\tools\freeze_baseline.py > "%EV%\baseline_freeze_run.log" 2>&1
if errorlevel 1 exit /b 8
py -3 F:\rawrxd\tools\certify_e2e.py > "%EV%\certification_run.log" 2>&1
if errorlevel 1 exit /b 8
py -3 F:\rawrxd\tools\write_tokenizer_cert.py >> "%EV%\certification_run.log" 2>&1
py -3 F:\rawrxd\tools\verify_e2e_cert.py > "%EV%\verification_run.log" 2>&1
if errorlevel 1 exit /b 8

type "%EV%\certification_run.log"
type "%EV%\verification_run.log"
echo REPRODUCTION_COMPLETE
exit /b 0
