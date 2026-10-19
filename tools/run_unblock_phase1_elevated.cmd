@echo off
REM Launch Phase 1 elevated. UAC prompt expected. Then REBOOT manually.
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"G:\~dev\rawrxd\tools\unblock_phase1.ps1\"' -Wait"
echo.
echo If P1_UNBLOCK_APPLIED.txt exists under G3_GPU1_AMDVLK_UNBLOCK_001\P1, REBOOT now.
echo After reboot: powershell -NoProfile -ExecutionPolicy Bypass -File G:\~dev\rawrxd\tools\verify_unblock_gate.ps1 -PhaseTag POST_P1
pause
