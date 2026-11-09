@echo off
setlocal EnableExtensions EnableDelayedExpansion
echo START %DATE% %TIME%>"F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\_run_c17_full_20261109-094755.out.txt"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\harness\chat_17_probe_matrix.ps1" -TipExe "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_chat_dispatch_001\TipChatDispatchC43B-Probe.exe" -SessionId "c17_full_20261109-094755" -RunId "c17_full_run_20261109-094755" -InterSendMs 400 >>"F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\_run_c17_full_20261109-094755.out.txt" 2>&1
echo EXIT=!ERRORLEVEL!>>"F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\_run_c17_full_20261109-094755.out.txt"
echo DONE>"F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\_run_c17_full_20261109-094755.DONE.txt"
