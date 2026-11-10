@echo off
set OUT=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\_hash_tip003_out.txt
echo ASOF=%DATE% %TIME%> "%OUT%"
certutil -hashfile "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_ext_host_002\RawrXD-Win32IDE-Native-Ext.exe" SHA256 >> "%OUT%" 2>&1
echo --- >> "%OUT%"
certutil -hashfile "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe" SHA256 >> "%OUT%" 2>&1
echo --- >> "%OUT%"
dir /b "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_ext_host_002\*.exe" >> "%OUT%" 2>&1
dir /b "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_ext_host_003\*.exe" >> "%OUT%" 2>&1
echo DONE>> "%OUT%"
exit /b 0
