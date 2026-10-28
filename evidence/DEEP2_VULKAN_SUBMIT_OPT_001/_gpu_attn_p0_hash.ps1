$ErrorActionPreference = 'Stop'
$evid = 'G:\~dev\rawrxd\evidence\DEEP2_VULKAN_SUBMIT_OPT_001'
$exe = 'F:\rawrxd\build_reap\bin\deep2_bench_tps.exe'
$spv = 'F:\rawrxd\tools\shaders\quant_attn_decode.spv'
$comp = 'F:\rawrxd\tools\shaders\quant_attn_decode.comp'
$model = 'G:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'
$exeH = (Get-FileHash $exe -Algorithm SHA256).Hash
$spvH = (Get-FileHash $spv -Algorithm SHA256).Hash
$compH = (Get-FileHash $comp -Algorithm SHA256).Hash
Write-Host "Hashing model (may take time)..."
$modelH = (Get-FileHash $model -Algorithm SHA256).Hash
$asof = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ssK')
@"
OPTIMIZED_SHA256=$exeH
SPV_SHA256=$spvH
COMP_SHA256=$compH
MODEL_SHA256=$modelH
EXE=$exe
SPV=$spv
COMP=$comp
MODEL=$model
NOTE=post DEEP2_ATTN_PARITY_DUMP rebuild + shared-softmax; NE != BASELINE B7CEAEEF675EB86023FF15EA1DB045B5C58634543EB7DD86A1F3E6680D4B0750
FLAGS=RAWRXD_NO_OLLAMA=1 RAWRXD_HOST_DECODE=1 DEEP2_MINIMAL_ENHANCE=1 DEEP2_WIDE_DOT_BATCH=1
ASOF=$asof
PROMOTE=0
"@ | Set-Content -Path (Join-Path $evid 'BENCH_SHA256_OPTIMIZED.txt') -Encoding utf8
Write-Host "OPTIMIZED_SHA256=$exeH"
Write-Host "SPV_SHA256=$spvH"
Write-Host "COMP_SHA256=$compH"
Write-Host "MODEL_SHA256=$modelH"
