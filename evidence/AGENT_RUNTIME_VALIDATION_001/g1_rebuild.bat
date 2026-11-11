@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
echo ===== BAT REBUILD %DATE% %TIME% =====>>"F:\rawrxd\evidence\AGENT_RUNTIME_VALIDATION_001\g1_build9.log"
cmake --build F:\rawrxd\build_win32ide --config Release --target RawrXD-Win32IDE-Native -- /m:1 /p:CL_MPCount=1 >>"F:\rawrxd\evidence\AGENT_RUNTIME_VALIDATION_001\g1_build9.log" 2>&1
set EC=%ERRORLEVEL%
> "F:\rawrxd\evidence\AGENT_RUNTIME_VALIDATION_001\BUILD_EXIT_CODE.txt" echo %EC%
echo BAT_DONE EC=%EC%>>"F:\rawrxd\evidence\AGENT_RUNTIME_VALIDATION_001\g1_build9.log"
exit /b %EC%
