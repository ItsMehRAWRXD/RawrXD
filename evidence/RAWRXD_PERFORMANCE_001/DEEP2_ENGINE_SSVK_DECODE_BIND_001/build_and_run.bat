@echo off
setlocal
set ROOT=%~dp0
set BUILD=G:\~dev\rawrxd\build_ninja
set MODEL=%~1
if "%MODEL%"=="" set MODEL=G:\~dev\rawrxd\llama3.2-3b-Q2_K.gguf
set RAWRXD_Q2K_PRODUCT_DECODE=1
set RAWRXD_GPU_FWD=1
cmake --build "%BUILD%" --target deep2_engine_ssvk_decode_bind_cert -j 8
if errorlevel 1 exit /b %errorlevel%
"%BUILD%\bin\deep2_engine_ssvk_decode_bind_cert.exe" "%MODEL%"
exit /b %errorlevel%
