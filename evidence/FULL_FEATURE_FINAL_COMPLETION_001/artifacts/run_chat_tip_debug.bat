@echo off
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
powershell -NoProfile -ExecutionPolicy Bypass -File "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\harness\chat_ctrl_enter_verify.ps1" -TipExe "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\candidates\tip_debug_001\RawrXD-Win32IDE-Native.exe" -OutDir "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts" -LogDir "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\chat_on_tip_debug"
exit /b %ERRORLEVEL%
