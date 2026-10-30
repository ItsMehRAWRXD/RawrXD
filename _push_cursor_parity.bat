@echo off
setlocal EnableExtensions
cd /d F:\rawrxd || exit /b 1
set GIT_OPTIONAL_LOCKS=0
set GIT_TERMINAL_PROMPT=0

echo === branch ===
git rev-parse --abbrev-ref HEAD
echo === add ===
git add -- ^
  src/agentic/tool_core.hpp ^
  src/agentic/ToolCallBridge.h ^
  src/agentic/AgentMode.cpp ^
  src/deep2/Deep2Engine.cpp ^
  _rebuild_agentic_cursor_parity.bat ^
  2>nul

if exist "F:\rawrxd-native-agent-001\evidence\AGENTIC_CURSOR_PARITY_001.txt" (
  if exist "evidence" (
    copy /Y "F:\rawrxd-native-agent-001\evidence\AGENTIC_CURSOR_PARITY_001.txt" "evidence\AGENTIC_CURSOR_PARITY_001.txt" >nul
    git add -- evidence/AGENTIC_CURSOR_PARITY_001.txt 2>nul
  )
)
if exist "F:\rawrxd-native-agent-001\evidence\E2E_FULL_AUTH_LEDGER_001.txt" (
  if exist "evidence" (
    copy /Y "F:\rawrxd-native-agent-001\evidence\E2E_FULL_AUTH_LEDGER_001.txt" "evidence\E2E_FULL_AUTH_LEDGER_001.txt" >nul
    git add -- evidence/E2E_FULL_AUTH_LEDGER_001.txt 2>nul
  )
)
if exist "F:\rawrxd-native-agent-001\evidence\LOCAL_MODEL_CERT_PLAN_001.txt" (
  if exist "evidence" (
    copy /Y "F:\rawrxd-native-agent-001\evidence\LOCAL_MODEL_CERT_PLAN_001.txt" "evidence\LOCAL_MODEL_CERT_PLAN_001.txt" >nul
    git add -- evidence/LOCAL_MODEL_CERT_PLAN_001.txt 2>nul
  )
)

echo === status (pathspec) ===
git status --short -- src/agentic/tool_core.hpp src/agentic/ToolCallBridge.h src/agentic/AgentMode.cpp src/deep2/Deep2Engine.cpp _rebuild_agentic_cursor_parity.bat evidence/AGENTIC_CURSOR_PARITY_001.txt evidence/E2E_FULL_AUTH_LEDGER_001.txt evidence/LOCAL_MODEL_CERT_PLAN_001.txt

echo === commit ===
git commit -m "Wire Cursor tool parity aliases and register runInTerminal." -m "Register Shell/Write/Delete handlers, remap Cursor args, canonicalize Ask-mode permissions so aliases cannot bypass runInTerminal denial. Dual-emit LinearW and MoEProxyStats on generate teardown. PROMOTE=0."
set EC=%ERRORLEVEL%
if %EC% neq 0 (
  echo COMMIT_EC=%EC% (may be nothing to commit)
)

echo === push ===
git push -u origin HEAD
set PEC=%ERRORLEVEL%
echo PUSH_EC=%PEC%
exit /b %PEC%
