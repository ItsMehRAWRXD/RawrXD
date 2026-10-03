@echo off
setlocal enabledelayedexpansion

set "LOGDIR=F:\~dev\audit_tombstone_001"
if not exist "%LOGDIR%" mkdir "%LOGDIR%"

echo ############################################################
echo # RAWRXD_DEEP2_SOVEREIGN_TOMBSTONE_001 - regression validator
echo # run: %DATE% %TIME%
echo ############################################################

call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
if errorlevel 1 (
  echo VCVARS_FAILED=1
  exit /b 90
)
echo VCVARS_OK=1

echo.
echo === STEP1_FRESH_CONFIGURE ===
cmake -S F:\~dev\rawrxd -B F:\~dev\build_tombstone_val -G Ninja -DCMAKE_BUILD_TYPE=Release > "%LOGDIR%\configure.log" 2>&1
set "CONFIGURE_EXIT=%errorlevel%"
echo CONFIGURE_EXIT=%CONFIGURE_EXIT%
echo CONFIGURE_TAIL_BEGIN
powershell -NoProfile -Command "Get-Content '%LOGDIR%\configure.log' -Tail 12"
echo CONFIGURE_TAIL_END

echo.
echo === STEP2_BUILD_RAWR_SERVER ===
ninja -C F:\~dev\build_rawr_ninja rawr-server > "%LOGDIR%\build.log" 2>&1
set "BUILD_EXIT=%errorlevel%"
echo BUILD_EXIT=%BUILD_EXIT%
if not "%BUILD_EXIT%"=="0" (
  echo BUILD_LOG_TAIL_BEGIN
  powershell -NoProfile -Command "Get-Content '%LOGDIR%\build.log' -Tail 40"
  echo BUILD_LOG_TAIL_END
)

echo.
echo === STEP3_ARTIFACT ===
if exist F:\~dev\build_rawr_ninja\bin\rawr-server.exe (
  for %%F in (F:\~dev\build_rawr_ninja\bin\rawr-server.exe) do (
    echo SERVER_EXE_SIZE=%%~zF
    echo SERVER_EXE_MTIME=%%~tF
  )
  set "HASH=" 
  for /f "skip=1 tokens=1" %%H in ('certutil -hashfile F:\~dev\build_rawr_ninja\bin\rawr-server.exe SHA256 ^| findstr /r "^[0-9a-fA-F]"') do set "HASH=%%H"
  echo SERVER_EXE_SHA256=!HASH!
) else (
  echo SERVER_EXE_MISSING=1
)

echo.
echo === STEP4_STALE_SERVERS_BEFORE ===
tasklist /FI "IMAGENAME eq rawr-server.exe" /NH

echo.
echo === STEP5_START_SERVER_PORT_21500 ===
start "rawr-server-val-21500" /b "F:\~dev\build_rawr_ninja\bin\rawr-server.exe" --model "G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf" --port 21500 --host 127.0.0.1 > "%LOGDIR%\server_21500.log" 2>&1
echo SERVER_LAUNCHED=1

set /a TRIES=0
:waitready
curl.exe -s -o nul "http://127.0.0.1:21500/health" >nul 2>&1
if not errorlevel 1 goto ready
set /a TRIES+=1
if !TRIES! GTR 300 (
  echo SERVER_NEVER_BECAME_READY
  echo SERVER_LOG_TAIL_BEGIN
  powershell -NoProfile -Command "Get-Content '%LOGDIR%\server_21500.log' -Tail 30"
  echo SERVER_LOG_TAIL_END
  goto cleanup
)
ping -n 3 127.0.0.1 >nul
goto waitready

:ready
echo SERVER_READY_AFTER_POLLS=!TRIES!

echo.
echo --- HEALTH ---
curl.exe -s -o "%LOGDIR%\health.json" -w "HEALTH_HTTP=%%{http_code}" "http://127.0.0.1:21500/health"
echo.
type "%LOGDIR%\health.json"
echo.

echo.
echo --- MODELS ---
curl.exe -s -o "%LOGDIR%\models.json" -w "MODELS_HTTP=%%{http_code}" "http://127.0.0.1:21500/v1/models"
echo.
type "%LOGDIR%\models.json"
echo.

echo.
echo --- CHAT_COMPLETIONS ---
set "CHATBODY={\"model\":\"tinyllama-1.1b-chat-v1.0.Q4_K_M\",\"messages\":[{\"role\":\"user\",\"content\":\"The capital of France is\"}],\"max_tokens\":12,\"temperature\":0,\"stream\":false}"
curl.exe -s -o "%LOGDIR%\chat.json" -w "CHAT_HTTP=%%{http_code}" -X POST -H "Content-Type: application/json" --data "!CHATBODY!" "http://127.0.0.1:21500/v1/chat/completions"
echo.
type "%LOGDIR%\chat.json"
echo.

echo.
echo --- TAGS_OLLAMA ---
curl.exe -s -o "%LOGDIR%\tags.json" -w "TAGS_HTTP=%%{http_code}" "http://127.0.0.1:21500/api/tags"
echo.
type "%LOGDIR%\tags.json"
echo.

:cleanup
echo.
echo === STEP6_FALSIFICATION_DEAD_PORT ===
curl.exe -s -S -o nul -w "DEADPORT_HTTP=%%{http_code}" "http://127.0.0.1:21999/health"
echo " DEADPORT_CURL_EXIT=%errorlevel%"

echo.
echo === STEP7_FALSIFICATION_BAD_MODEL ===
start "rawr-server-badmodel" /b "F:\~dev\build_rawr_ninja\bin\rawr-server.exe" --model "F:\~definitely\not\a\real\model.gguf" --port 21501 --host 127.0.0.1 > "%LOGDIR%\server_badmodel.log" 2>&1
ping -n 25 127.0.0.1 >nul
curl.exe -s -o "%LOGDIR%\badmodel_health.json" -w "BADMODEL_HEALTH_HTTP=%%{http_code}" "http://127.0.0.1:21501/health"
echo.
if exist "%LOGDIR%\badmodel_health.json" type "%LOGDIR%\badmodel_health.json"
echo.
echo BADMODEL_LOG_TAIL_BEGIN
powershell -NoProfile -Command "if (Test-Path '%LOGDIR%\server_badmodel.log') { Get-Content '%LOGDIR%\server_badmodel.log' -Tail 20 }"
echo BADMODEL_LOG_TAIL_END

echo.
echo === STEP8_KILL_ALL_RAWR_SERVER ===
taskkill /IM rawr-server.exe /F 2>&1

echo.
echo === STEP9_SOURCE_VERIFICATION ===
echo --- git status of the two touched paths ---
git -C F:\~dev status --porcelain -- rawrxd/src/deep2/Deep2Server_Sovereign.cpp rawrxd/CMakeLists.txt
echo --- every remaining Deep2Server_Sovereign mention in CMakeLists (expect comments only) ---
rg -n "Deep2Server_Sovereign" F:\~dev\rawrxd\CMakeLists.txt
echo --- bare source-list entries (expect none) ---
rg -n "^\s*src/deep2/Deep2Server_Sovereign\.cpp\s*$" F:\~dev\rawrxd\CMakeLists.txt
echo BARE_SOURCE_ENTRY_COUNT_DONE
echo --- STUB marker count in the retired file (expect 0) ---
rg -c "^// STUB:" F:\~dev\rawrxd\src\deep2\Deep2Server_Sovereign.cpp
echo STUB_MARKER_SCAN_DONE
echo --- non-comment, non-blank lines in the retired file (expect 0) ---
rg -n -v "^\s*(//.*)?$" F:\~dev\rawrxd\src\deep2\Deep2Server_Sovereign.cpp
echo CODE_LINE_SCAN_DONE

echo.
echo ############################################################
echo # VALIDATOR_DONE
echo ############################################################
endlocal
