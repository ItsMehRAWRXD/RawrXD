@echo off
"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe" -y "srv*;D:\rawrxd\build_win32ide\tests" -cf "D:\rawrxd\cdb_cmds.txt" "D:\rawrxd\build_win32ide\tests\RawrXD-VulkanValidationTax.exe" --iterations 1000 --mode=guards-off > "D:\rawrxd\cdb_type_capture_postfix.txt" 2>&1
