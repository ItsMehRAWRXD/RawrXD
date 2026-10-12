param([int]$Repeats = 3)
$exe = "tmp_build_mg\rawrxd_modelgenie_ir_executor.exe"
$gguf = "F:\rawrxd\DeepSeek-V2-Lite-Chat.Q4_K_M.gguf"
$ev = "F:\rawrxd\tmp_build_mg\ev"
for ($i = 1; $i -le $Repeats; $i++) {
    & $exe $gguf $ev --teacher-forced 1 185 16 15 2> "tmp_build_mg\run_rep$i.txt" | Out-Null
    $vals = (Select-String -Path "tmp_build_mg\run_rep$i.txt" -Pattern "max_val" | ForEach-Object { $_.Line })
    Write-Output "repeat $i : $($vals -join ' | ')"
}
