$env:DEEP2_SPEC_GPU_ATTN='1'
$exe='F:\~dev\build_p2\Release\qwen32_85tps_gate.exe'
$model='F:\models\Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf'

# Clear old logs
if(Test-Path 'F:\~dev\qwen32_85tps_gate_internal.log'){ Remove-Item 'F:\~dev\qwen32_85tps_gate_internal.log' -Force }
if(Test-Path 'F:\~dev\deep2_attn_authority.log'){ Remove-Item 'F:\~dev\deep2_attn_authority.log' -Force }

# Run the binary
$proc = Start-Process -FilePath $exe -ArgumentList $model,"--only","4" -Wait -PassThru
$exit = $proc.ExitCode

# Now read the self-log files
$gateLog = ''
$attnLog = ''
if(Test-Path 'F:\~dev\qwen32_85tps_gate_internal.log'){
    $gateLog = Get-Content 'F:\~dev\qwen32_85tps_gate_internal.log' -Raw
}
if(Test-Path 'F:\~dev\deep2_attn_authority.log'){
    $attnLog = Get-Content 'F:\~dev\deep2_attn_authority.log' -Raw
}

# Output seal condition
$attnGpu = ([regex]::Matches($attnLog, 'ATTN_GPU_OK')).Count
$attnCpu = ([regex]::Matches($attnLog, 'ATTN_CPU_FALLBACK')).Count
$deviceLost = ([regex]::Matches($gateLog, 'DEVICE_LOST')).Count
$stackCookie = ([regex]::Matches($gateLog, '0xC0000409')).Count
$pass = ([regex]::Matches($gateLog, 'THRESHOLD_RESULT ntok=4 PASS')).Count

Write-Output "NTOK4_EXIT=$exit"
Write-Output "THRESHOLD_PASS=$pass"
Write-Output "ATTN_GPU_OK=$attnGpu"
Write-Output "ATTN_CPU_FALLBACK=$attnCpu"
Write-Output "DEVICE_LOST=$deviceLost"
Write-Output "0xC0000409=$stackCookie"
