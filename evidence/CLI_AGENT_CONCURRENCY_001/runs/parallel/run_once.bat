@echo off
set RAWR_AGENT_FORCE_TOOL=read,report
set RAWR_PARALLEL_LANES=1
set RAWR_AGENT_FORCE_PATH=g:\~dev\rawrxd\evidence\CLI_AGENT_CONCURRENCY_001\runs\parallel\ws\README.md
"g:\~dev\rawrxd\build_ninja\bin\rawr.exe" agent tinyllama.gguf --workspace "g:\~dev\rawrxd\evidence\CLI_AGENT_CONCURRENCY_001\runs\parallel\ws" --auto=full --max-tokens 8 > "g:\~dev\rawrxd\evidence\CLI_AGENT_CONCURRENCY_001\runs\parallel\run.out.txt" 2> "g:\~dev\rawrxd\evidence\CLI_AGENT_CONCURRENCY_001\runs\parallel\run.err.txt"
> "g:\~dev\rawrxd\evidence\CLI_AGENT_CONCURRENCY_001\runs\parallel\run.exit.txt" echo EXIT=%ERRORLEVEL%
