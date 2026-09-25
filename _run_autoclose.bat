@echo off
setlocal
set RAWRXD_AUTOCLOSE_DEBUG=1
set RAWRXD_AUTOCLOSE_GEN=1
set RAWRXD_AUTOCLOSE_LAYERS=26
"f:\~dev\rawrxd\win32ide_strict\build_v4\Release\RawrXD-Win32IDE.exe" --autoclose --model "D:\rawrxd\gemma3-1b-Q2_K.gguf" --workspace "F:\~dev\rawrxd" --gate-tokens 8 --nonce 7E91B462 --receipt "f:\~dev\rawrxd\win32ide_strict\build_v4\Release\bat_receipt.txt" --wall-ms 300000
endlocal
