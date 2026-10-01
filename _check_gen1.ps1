$Logs = 'F:\~dev\rawrxd\audit\RAWRXD_IDE_CMAKE_FULL_AUDIT_001'
$gen1Log = Join-Path $Logs 'BATCH_2_CLOSURE_item10_gen1.log'
$summary = Join-Path $Logs 'BATCH_2_CLOSURE_item10_gen1_summary.txt'

$content = Get-Content $gen1Log -Raw
$lines = $content -split "`n"

"B count: $((($lines | Select-String -Pattern '^B\[\d+\]').Count))" | Out-File $summary
"D count: $((($lines | Select-String -Pattern '^D\[\d+\]').Count))" | Out-File $summary -Append
"Verdict lines:" | Out-File $summary -Append
($lines | Select-String -Pattern 'VERDICT|GENERATION_|SAME_|INHERITED|FORWARD_FAILURE|CANCELLED|COMPLETED_WITH|RESULT_CONTRACT') | ForEach-Object {
    "$($_.Line)" | Out-File $summary -Append
}
"Exit code:" | Out-File $summary -Append
($lines | Select-String -Pattern 'EXIT_CODE') | ForEach-Object { "$($_.Line)" | Out-File $summary -Append }
"Log size: $((Get-Item $gen1Log).Length)" | Out-File $summary -Append
"Last 3 lines:" | Out-File $summary -Append
($lines | Select-Object -Last 3) | ForEach-Object { "$_" | Out-File $summary -Append }

Get-Content $summary
