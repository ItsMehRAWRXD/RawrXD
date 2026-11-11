@echo off
setlocal
echo START %DATE% %TIME%>"F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\_run_c17_excl_20261109-093130.out.txt"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\harness\chat_17_probe_matrix.ps1" -TipExe "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_chat_dispatch_001\TipChatDispatchC43B-Probe.exe" -SessionId "c17_excl_20261109-093130" -RunId "c17_excl_run_20261109-093130" -InterSendMs 400 >>"F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\_run_c17_excl_20261109-093130.out.txt" 2>&1
echo EXIT=!ERRORLEVEL!>>"F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\_run_c17_excl_20261109-093130.out.txt"
echo DONE>%marker%
echo SESSION_ID=c17_excl_20261109-093130> "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\_run_c17_excl_20261109-093130.META.txt"
echo RUN_ID=c17_excl_run_20261109-093130>> "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\_run_c17_excl_20261109-093130.META.txt"
echo TIP_SHA256=C43B01ABE886700B7A085C570575CCB9DED63A140000380ADCBE07ADEF33A629>> "F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\_run_c17_excl_20261109-093130.META.txt"
