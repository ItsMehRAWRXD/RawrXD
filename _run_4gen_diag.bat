@echo off
setlocal
set "EXE=F:\~dev\rawrxd\bin\deep2_generation_lifecycle_test.exe"
set "MODEL=F:\OllamaModels\blobs\sha256-5c19f6282f4fc51cb114cb6c876d70ca2fc3b9cf0fbd0a018d9908f4fe1f63b3"
set "LOG=F:\~dev\rawrxd\audit\RAWRXD_IDE_CMAKE_FULL_AUDIT_001\BATCH_2_CLOSURE_item10_4gen_diag.log"
echo Running with diag build, log to: %LOG%
"%EXE%" "%MODEL%" --generations 4 --max-tokens 4 > "%LOG%" 2>&1
echo EXIT_CODE=%errorlevel%
endlocal
