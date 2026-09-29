@echo off
cd /d F:\~dev\rawrxd
cmake --build build_w1 --config Release --target RawrXD-Win32IDE -j 4 > F:\~dev\_w1_build49.txt 2>&1
echo BUILD_EXIT=%ERRORLEVEL% > F:\~dev\_w1_build49_done.txt
