@echo off
setlocal enabledelayedexpansion

echo === STEP6_FALSIFICATION_DEAD_PORT ===
curl.exe -s -S -o nul -w "DEADPORT_HTTP=%%{http_code}" "http://127.0.0.1:21999/health"
echo.
echo DEADPORT_CURL_EXIT=%errorlevel%

echo.
echo === STEP7_FALSIFICATION_BAD_MODEL ===
if exist "F:\~dev\build_rawr_ninja\bin\rawr-server.exe" (
  start "rawr-server-badmodel" /b "F:\~dev\build_rawr_ninja\bin\rawr-server.exe" --model "F:\~definitely\not\a\real\model.gguf" --port 21501 --host 127.0.0.1 > "F:\~dev\audit_tombstone_001\server_badmodel.log" 2>&1
  ping -n 25 127.0.0.1 >nul
  curl.exe -s -o "F:\~dev\audit_tombstone_001\badmodel_health.json" -w "BADMODEL_HEALTH_HTTP=%%{http_code}" "http://127.0.0.1:21501/health"
  echo.
  if exist "F:\~dev\audit_tombstone_001\badmodel_health.json" type "F:\~dev\audit_tombstone_001\badmodel_health.json"
  echo.
  echo BADMODEL_LOG_TAIL_BEGIN
  powershell -NoProfile -Command "if (Test-Path 'F:\~dev\audit_tombstone_001\server_badmodel.log') { Get-Content 'F:\~dev\audit_tombstone_001\server_badmodel.log' -Tail 20 }"
  echo BADMODEL_LOG_TAIL_END
) else (
  echo BADMODEL_BINARY_MISSING=1
  echo (rawr-server.exe does not exist - cannot start bad model test)
)

echo.
echo === STEP8_KILL_ALL_RAWR_SERVER ===
taskkill /IM rawr-server.exe /F 2>&1

echo.
echo === STEP9_SOURCE_VERIFICATION ===
echo --- git status of the two touched paths ---
git -C F:\~dev status --porcelain -- rawrxd/src/deep2/Deep2Server_Sovereign.cpp rawrxd/CMakeLists.txt
echo.
echo --- every remaining Deep2Server_Sovereign mention in CMakeLists (expect comments only) ---
rg -n "Deep2Server_Sovereign" F:\~dev\rawrxd\CMakeLists.txt
echo RG_END_CMAKE
echo.
echo --- bare source-list entries (expect none) ---
rg -n "^\s*src/deep2/Deep2Server_Sovereign\.cpp\s*$" F:\~dev\rawrxd\CMakeLists.txt
echo BARE_SOURCE_ENTRY_COUNT_DONE
echo.
echo --- STUB marker count in the retired file (expect 0) ---
rg -c "^// STUB:" F:\~dev\rawrxd\src\deep2\Deep2Server_Sovereign.cpp
echo STUB_MARKER_SCAN_DONE
echo.
echo --- non-comment, non-blank lines in the retired file (expect 0) ---
rg -n -v "^\s*(//.*)?$" F:\~dev\rawrxd\src\deep2\Deep2Server_Sovereign.cpp
echo CODE_LINE_SCAN_DONE

echo.
echo --- Checking for stale server on port 21435 ---
curl.exe -s -o nul -w "STALE_21435_HTTP=%%{http_code}" "http://127.0.0.1:21435/health" 2>&1
echo.
echo STALE_21435_CURL_EXIT=%errorlevel%

echo.
echo ############################################################
echo # REMAINING_STEPS_DONE
echo ############################################################
