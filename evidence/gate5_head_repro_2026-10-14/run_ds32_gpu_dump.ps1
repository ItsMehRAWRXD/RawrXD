$ErrorActionPreference='Stop'
$E='F:\rawrxd\evidence\gate5_head_repro_2026-10-14'
$out="$E\deepseek32\d2_gpu_head"
Remove-Item "$E\deepseek32\d2_gpu_head" -Recurse -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $out | Out-Null
$toks=(Get-Content "$E\tok32.txt").Trim()
$env:PATH='F:\rawrxd\build_ggml_profiler\bin\Release;'+$env:PATH
& 'F:\rawrxd\tools\deep2_bench_tps.exe' --model 'F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf' --tokens $toks --decode 1 --dump-logits $out > "$E\deepseek32_gpu_dump.log" 2>&1
$rc=$LASTEXITCODE
$files = (Get-ChildItem $out -File -ErrorAction SilentlyContinue|Measure-Object).Count
"DS32_GPU_DONE rc=$rc files=$files"
