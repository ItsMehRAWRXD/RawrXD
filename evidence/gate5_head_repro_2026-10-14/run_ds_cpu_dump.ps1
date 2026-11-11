$ErrorActionPreference='Stop'
$E='F:\rawrxd\evidence\gate5_head_repro_2026-10-14'
$out="$E\deepseek32\d2_cpu_head"
New-Item -ItemType Directory -Force -Path $out | Out-Null
$toks=(Get-Content "$E\tok16.txt").Trim()
$env:PATH='F:\rawrxd\build_ggml_profiler\bin\Release;'+$env:PATH
& 'F:\rawrxd\tools\deep2_bench_tps.exe' --model 'F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf' --tokens $toks --decode 1 --cpu --dump-logits $out > "$E\deepseek32_cpu_dump.log" 2>&1
$rc=$LASTEXITCODE
$files=(Get-ChildItem $out -File -ErrorAction SilentlyContinue|Measure-Object).Count
"DS16_CPU_DONE rc=$rc files=$files"
