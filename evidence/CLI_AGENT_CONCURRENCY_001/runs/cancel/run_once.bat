@echo off
set RAWR_AGENT_FORCE_TOOL=read,patch,build,test,report
set RAWR_AGENT_FORCE_PATH=g:\~dev\rawrxd\evidence\CLI_AGENT_CONCURRENCY_001\runs\cancel\ws\scratch\note.txt
set RAWR_AGENT_FORCE_CONTENT=cancel_probe_patch
"g:\~dev\rawrxd\build_ninja\bin\rawr.exe" agent tinyllama.gguf --workspace "g:\~dev\rawrxd\evidence\CLI_AGENT_CONCURRENCY_001\runs\cancel\ws" --auto=full --max-tokens 8 > "g:\~dev\rawrxd\evidence\CLI_AGENT_CONCURRENCY_001\runs\cancel\run.out.txt" 2> "g:\~dev\rawrxd\evidence\CLI_AGENT_CONCURRENCY_001\runs\cancel\run.err.txt"
> "g:\~dev\rawrxd\evidence\CLI_AGENT_CONCURRENCY_001\runs\cancel\run.exit.txt" echo EXIT=%ERRORLEVEL%
