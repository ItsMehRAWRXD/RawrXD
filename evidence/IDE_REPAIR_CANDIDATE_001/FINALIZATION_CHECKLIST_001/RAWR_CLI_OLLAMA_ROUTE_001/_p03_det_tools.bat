@echo off
setlocal
set EXE=F:\rawrxd\build_tip_debug_rel\bin-msvc\rawr.exe
set EV=F:\rawrxd\evidence\IDE_REPAIR_CANDIDATE_001\FINALIZATION_CHECKLIST_001\RAWR_CLI_OLLAMA_ROUTE_001
cd /d F:\rawrxd

set /p READ_JSON=<"%EV%\_p03_args_read.json"
"%EXE%" tool read_file "%READ_JSON%" --mode code --json > "%EV%\_p03_det_read.json" 2> "%EV%\_p03_det_read.err.txt"
echo READ_EXIT=%ERRORLEVEL%

set /p EDIT_JSON=<"%EV%\_p03_args_edit.json"
"%EXE%" tool edit_files "%EDIT_JSON%" --mode code --json > "%EV%\_p03_det_edit.json" 2> "%EV%\_p03_det_edit.err.txt"
echo EDIT_EXIT=%ERRORLEVEL%

set /p BUILD_JSON=<"%EV%\_p03_args_build.json"
"%EXE%" tool run_build "%BUILD_JSON%" --mode code --json > "%EV%\_p03_det_build.json" 2> "%EV%\_p03_det_build.err.txt"
echo BUILD_EXIT=%ERRORLEVEL%

set /p TEST_JSON=<"%EV%\_p03_args_test.json"
"%EXE%" tool run_tests "%TEST_JSON%" --mode code --json > "%EV%\_p03_det_test.json" 2> "%EV%\_p03_det_test.err.txt"
echo TEST_EXIT=%ERRORLEVEL%