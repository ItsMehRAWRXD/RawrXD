@echo off
REM Daily streamer V0 smoke — does NOT touch Attempt2 / cert benchmark binary
setlocal
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
cd /d "%~dp0"
cl /nologo /TC /O2 /W3 /MT /I. /c d2_stream_metrics.c d2_token_sink.c d2_session_mock.c d2_stream_session.c d2_streamer_main.c || exit /b 1
link /nologo /subsystem:console d2_stream_metrics.obj d2_token_sink.obj d2_session_mock.obj d2_stream_session.obj d2_streamer_main.obj kernel32.lib /out:deep2_streamer.exe || exit /b 1
deep2_streamer.exe --model mock://daily-v0
echo DAILY_STREAMER_SMOKE_EXIT=%ERRORLEVEL%
echo ATTEMPT2_ISOLATION=1
echo CERT_BINARY_TOUCHED=0
echo FULL_MODEL_TPS_AUTHORITY=0
echo PROMOTE=0
exit /b %ERRORLEVEL%
