@echo off
echo Starting manifest generation...
py -3 "F:\~dev\rawrxd_recovery_20260922\gen_g_manifest.py" > "F:\~dev\rawrxd_recovery_20260922\manifest_g_log.txt" 2>&1
echo Exit code: %ERRORLEVEL%
pause
