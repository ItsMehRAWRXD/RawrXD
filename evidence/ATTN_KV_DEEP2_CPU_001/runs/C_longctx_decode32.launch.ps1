$ErrorActionPreference='Continue'
Set-Location 'g:\~dev\rawrxd\build_ninja\bin'
$env:RAWRXD_HOST_DECODE='1'
$env:R1_HOST_FLOOR='1'
$env:RAWRXD_ALLOW_GPU='0'
$env:DEEP2_WEIGHT_BUDGET_MIB='8192'
$prompt = [IO.File]::ReadAllText('g:\~dev\rawrxd\evidence\ATTN_KV_DEEP2_CPU_001\runs\C_longctx_decode32.prompt.txt')
$argList = @('run','g:\~dev\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf','-p',$prompt,'--max-tokens','32','--receipt','g:\~dev\rawrxd\evidence\ATTN_KV_DEEP2_CPU_001\runs\C_longctx_decode32.receipt.json')
$p = Start-Process -FilePath 'g:\~dev\rawrxd\build_ninja\bin\rawr.exe' -ArgumentList $argList -NoNewWindow -PassThru -RedirectStandardOutput 'g:\~dev\rawrxd\evidence\ATTN_KV_DEEP2_CPU_001\runs\C_longctx_decode32.out.txt' -RedirectStandardError 'g:\~dev\rawrxd\evidence\ATTN_KV_DEEP2_CPU_001\runs\C_longctx_decode32.err.txt'
$ok = $p.WaitForExit(600000)
if (-not $ok) { Stop-Process -Id $p.Id -Force; Set-Content 'g:\~dev\rawrxd\evidence\ATTN_KV_DEEP2_CPU_001\runs\C_longctx_decode32.exit.txt' 'EXIT=TIMEOUT' } else { Set-Content 'g:\~dev\rawrxd\evidence\ATTN_KV_DEEP2_CPU_001\runs\C_longctx_decode32.exit.txt' ("EXIT=" + $p.ExitCode) }
