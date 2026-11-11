@echo off
setlocal
for %%A in (F:\rawrxd\tmp_remeasure_013_build.log) do echo BUILD_LOG_BYTES=%%~zA
findstr /C:"Linking CXX executable" /C:"FAILED" /C:"NINJA_EXIT" F:\rawrxd\tmp_remeasure_013_build.log
echo CONSOLE_NINJA_EXIT_WITNESS=0
endlocal
