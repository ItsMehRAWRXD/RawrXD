@echo off
set DUMPBIN=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64\dumpbin.exe
set OBJ=G:\~dev\rawrxd\evidence\WATCHDOG_ASM_BIND_001\RawrXD_Watchdog_from_source.obj
"%DUMPBIN%" /SYMBOLS "%OBJ%" > "G:\~dev\rawrxd\evidence\WATCHDOG_ASM_BIND_001\dumpbin_symbols.txt" 2>&1
echo EXIT=%ERRORLEVEL%
findstr /I "asm_watchdog hmac External" "G:\~dev\rawrxd\evidence\WATCHDOG_ASM_BIND_001\dumpbin_symbols.txt"
