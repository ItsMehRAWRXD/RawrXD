@echo off
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x64 >nul 2>&1
cd /d "F:\~dev\rawrxd\evidence\RAWRXD_STUB_RECONCILIATION_001\BATCH_0"
cl /nologo /std:c++20 /EHsc /O2 /W4 /utf-8 /I "F:\~dev\rawrxd\src" ^
   lease_tool.cpp ^
   "F:\~dev\rawrxd\src\agentmodes\WriterLeaseAuthority.cpp" ^
   "F:\~dev\rawrxd\src\agentmodes\RawrCertAuthority.cpp" ^
   "F:\~dev\rawrxd\src\agentmodes\RawrReceiptValidator.cpp" ^
   "F:\~dev\rawrxd\src\deep2\ReceiptAuthority.cpp" ^
   /Fe:lease_tool.exe bcrypt.lib
if errorlevel 1 (
  echo LEASE_TOOL_COMPILE_FAILED
  exit /b 1
)
echo LEASE_TOOL_COMPILE_OK
exit /b 0
