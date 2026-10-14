$ErrorActionPreference='Stop'
$E='F:\rawrxd\evidence\gate5_head_repro_2026-10-14\dualgpu'
Remove-Item $E -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $E | Out-Null
$env:PATH='F:\rawrxd\build_ggml_profiler\bin\Release;'+$env:PATH
$bm='F:\rawrxd\tools\deep2_bench_tps.exe'
$m='F:\rawrxd\models\tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf'
# A: device 0 (Radeon AI PRO R9700, score-select default); B: device 4 (RX 7800 XT, pinned)
$argsA=@('--model',$m,'--decode','12','--runs','1')
$argsB=@('--model',$m,'--decode','12','--runs','1','--device','4')
$t0=Get-Date
$a=Start-Process -FilePath $bm -ArgumentList $argsA -NoNewWindow -PassThru -RedirectStandardOutput "$E\dev0.log" -RedirectStandardError "$E\dev0.err"
$b=Start-Process -FilePath $bm -ArgumentList $argsB -NoNewWindow -PassThru -RedirectStandardOutput "$E\dev4.log" -RedirectStandardError "$E\dev4.err"
$samples=0; $both=0
while((-not $a.HasExited) -or (-not $b.HasExited)){
  $samples++; if((-not $a.HasExited) -and (-not $b.HasExited)) { $both++ }
  Start-Sleep -Milliseconds 150
}
$a.WaitForExit(); $b.WaitForExit()
$wall=[int]((Get-Date)-$t0).TotalMilliseconds
"CONCURRENCY wall_ms=$wall samples=$samples samples_both_gpus_busy=$both"
"devA(R9700) rc=$($a.ExitCode)  devB(7800XT) rc=$($b.ExitCode)"
