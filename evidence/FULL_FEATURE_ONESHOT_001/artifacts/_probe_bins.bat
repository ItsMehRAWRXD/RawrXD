@echo off
set OUT=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\bin_probe.txt
echo PROBE_START>%OUT%
echo %DATE% %TIME%>>%OUT%
dir /a /-c "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_ext_host_002\*.exe" >>%OUT% 2>&1
dir /a /-c "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\*.exe" >>%OUT% 2>&1
dir /a /-c "F:\rawrxd\build_tip_ext_host_001\*.exe" >>%OUT% 2>&1
dir /s /b "F:\rawrxd\build_tip_ext_host_001\*Native*.exe" >>%OUT% 2>&1
dir /s /b "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\*Native*.exe" >>%OUT% 2>&1
where /R F:\rawrxd RawrXD-Win32IDE-Native-Ext.exe >>%OUT% 2>&1
echo PROBE_END>>%OUT%
exit /b 0
