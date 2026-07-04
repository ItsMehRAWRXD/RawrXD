$Script:todos = Import-Csv "all_todos.csv"
$Script:filtered = $todos | Where-Object { $_.Text -match "TODO" }
$Script:output = "Total TODOs: $($filtered.Count)`n"
$output += ($filtered | Select-Object -First 20 | Format-Table -AutoSize | Out-String)
Set-Content -Path "todo_analysis.txt" -Value $output