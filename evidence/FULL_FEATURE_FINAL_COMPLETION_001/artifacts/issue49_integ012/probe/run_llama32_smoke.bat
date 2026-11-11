@echo off
setlocal
taskkill /F /IM deep2_agentic_loop.exe >nul 2>&1
taskkill /F /IM RawrXD-Win32IDE-Native-Ext.exe >nul 2>&1
ping -n 3 127.0.0.1 >nul
set RAWRXD_FORCE_LOCAL_AGENTIC=1
set RAWRXD_ISSUE49_HOST_SEED=0
cd /d "F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project"
"F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\candidates\tip_final_integ_012\deep2_agentic_loop.exe" --model "F:\rawrxd\llama3.2-3b-Q3_K_S.gguf" --workdir "F:\rawrxd\evidence\CC79_RUNTIME_001\fixtures\issue49_project" --target-file bug.cpp --task "Fix bug.cpp so undeclared_fn(1,2) compiles. Reply TOOL read_motd first." --max-steps 3 --max-new 64 --max-wall-time-sec 480 --prefill-chunk 32 > "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ012\probe\followup4_llama32_tool_smoke.log" 2>&1
echo EXIT=%ERRORLEVEL%>> "F:\rawrxd\evidence\FULL_FEATURE_FINAL_COMPLETION_001\artifacts\issue49_integ012\probe\followup4_llama32_tool_smoke.log"
