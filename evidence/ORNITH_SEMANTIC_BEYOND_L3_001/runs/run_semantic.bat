@echo off
setlocal
set RAWRXD_DEEP2_ALLOW_EXPERIMENTAL_SSM=1
cd /d g:\~dev\rawrxd
"g:\~dev\rawrxd\evidence\REAP_STRATA_UNSLOTH_OLLAMA_BENCH_001\bin_pin\probe_rawr.exe.r103_moe.exe" run "F:\OllamaModels\_REAP16\ornith-1_5-35b-REAP194\sha256-aaeb640f98a892980ef54876024293cc8d6987a86523aa1b947ffa9274ef800a" -p "Say hi in one short sentence." --max-tokens 8 >"g:\~dev\rawrxd\evidence\ORNITH_SEMANTIC_BEYOND_L3_001\runs\ornith_semantic.out.log" 2>"g:\~dev\rawrxd\evidence\ORNITH_SEMANTIC_BEYOND_L3_001\runs\ornith_semantic.err.log"
echo %ERRORLEVEL%>"g:\~dev\rawrxd\evidence\ORNITH_SEMANTIC_BEYOND_L3_001\runs\ornith_semantic.exit.txt"
