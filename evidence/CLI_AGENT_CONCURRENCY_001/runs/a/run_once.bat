@echo off
set RAWR_AGENT_FORCE_TOOL=read,patch,build,test,report
set RAWR_AGENT_FORCE_PATH=g:\~dev\rawrxd\evidence\CLI_AGENT_CONCURRENCY_001\runs\a\ws\scratch\note.txt
set RAWR_AGENT_FORCE_CONTENT=patched_by_A_CONCURRENCY
"g:\~dev\rawrxd\build_ninja\bin\rawr.exe" agent tinyllama.gguf --workspace "g:\~dev\rawrxd\evidence\CLI_AGENT_CONCURRENCY_001\runs\a\ws" --auto=full --max-tokens 8 > "g:\~dev\rawrxd\evidence\CLI_AGENT_CONCURRENCY_001\runs\a\run.out.txt" 2> "g:\~dev\rawrxd\evidence\CLI_AGENT_CONCURRENCY_001\runs\a\run.err.txt"
echo EXIT=%ERRORLEVEL%> "g:\~dev\rawrxd\evidence\CLI_AGENT_CONCURRENCY_001\runs\a\run.exit.txt"
