@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run_corpus.ps1"
exit /b %ERRORLEVEL%
