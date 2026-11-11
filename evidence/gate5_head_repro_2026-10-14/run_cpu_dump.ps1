$ErrorActionPreference='Stop'
$E='F:\rawrxd\evidence\gate5_head_repro_2026-10-14'
$M='F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'
$tf='F:\rawrxd\evidence\GAP_AUDIT_2026-10-13\gate5\tokens_long.txt'
$toks=((Get-Content $tf).Trim() -split '\s+' | Where-Object {$_ -ne ''}) -join ' '
$env:PATH='F:\rawrxd\build_ggml_profiler\bin\Release;'+$env:PATH
& 'F:\rawrxd\tools\deep2_bench_tps.exe' --model $M --tokens $toks --decode 1 --cpu --dump-logits "$E\d2_cpu_head" > "$E\d2_cpu_head.log" 2>&1
$rc=$LASTEXITCODE
$n=(Get-ChildItem "$E\d2_cpu_head" -File -ErrorAction SilentlyContinue|Measure-Object).Count
"cpu_dump_rc=$rc files=$n"
