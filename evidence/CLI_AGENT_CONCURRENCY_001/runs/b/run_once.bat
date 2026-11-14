@echo off
set RAWR_AGENT_FORCE_TOOL=read,patch,build,test,report
set RAWR_AGENT_FORCE_PATH=g:\~dev\rawrxd\evidence\CLI_AGENT_CONCURRENCY_001\runs\b\ws\scratch\note.txt
set RAWR_AGENT_FORCE_CONTENT=patched_by_B_CONCURRENCY
"g:\~dev\rawrxd\build_ninja\bin\rawr.exe" agent tinyllama.gguf --workspace "g:\~dev\rawrxd\evidence\CLI_AGENT_CONCURRENCY_001\runs\b\ws" --auto=full --max-tokens 8 > "g:\~dev\rawrxd\evidence\CLI_AGENT_CONCURRENCY_001\runs\b\run.out.txt" 2> "g:\~dev\rawrxd\evidence\CLI_AGENT_CONCURRENCY_001\runs\b\run.err.txt"
echo EXIT=%ERRORLEVEL%> "g:\~dev\rawrxd\evidence\CLI_AGENT_CONCURRENCY_001\runs\b\run.exit.txt"
