$ErrorActionPreference='Stop'
$E='F:\rawrxd\evidence\gate5_head_repro_2026-10-14'
$toks=(Get-Content "$E\tok64.txt").Trim()
$env:PATH='F:\rawrxd\build_ggml_profiler\bin\Release;'+$env:PATH
& 'F:\rawrxd\tools\deep2_bench_tps.exe' --model 'F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf' --tokens $toks --decode 1 --dump-logits "$E\deepseek\d2_gpu_head" > "$E\deepseek_gpu_dump.log" 2>&1
$rc=$LASTEXITCODE
$b=(Get-ChildItem "$E\deepseek\d2_gpu_head" -File -ErrorAction SilentlyContinue | Select-Object -First 1)
$vocab = if($b){$b.Length/4}else{'NA'}
$files = (Get-ChildItem "$E\deepseek\d2_gpu_head" -File -ErrorAction SilentlyContinue|Measure-Object).Count
"DS_GPU_DONE rc=$rc vocab=$vocab files=$files"
