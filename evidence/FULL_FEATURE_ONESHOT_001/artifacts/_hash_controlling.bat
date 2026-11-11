@echo off
set OUT=F:\rawrxd\evidence\FULL_FEATURE_ONESHOT_001\artifacts\controlling_hashes.txt
> "%OUT%" echo HASH_START
>>"%OUT%" echo %DATE% %TIME%
certutil -hashfile "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_ext_host_002\RawrXD-Win32IDE-Native-Ext.exe" SHA256 >>"%OUT%"
certutil -hashfile "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\RawrXD-Win32IDE-Native.exe" SHA256 >>"%OUT%"
certutil -hashfile "F:\rawrxd\evidence\DAILY_DRIVER_CLOSE_001\package\tip_ext_host_002\RawrXD-Win32IDE-Native.exe" SHA256 >>"%OUT%"
>>"%OUT%" echo HASH_END
exit /b 0
