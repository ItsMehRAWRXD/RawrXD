@echo off
echo === Test: strata.exe generation ===
"F:\rawrxd\external\strata\components-rx9070\engine\0.1.59-windows-x86_64-hip-rx9070\strata.exe" --pack "F:\rawrxd\external\strata\components-rx9070\engine\0.1.59-windows-x86_64-hip-rx9070" --tokens "1,2,3,4,5" --max-new 10 --stats 2>&1
