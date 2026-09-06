Get-WinEvent -FilterHashtable @{LogName='Application'; Level=2; StartTime=(Get-Date).AddMinutes(-30)} -MaxEvents 8 -ErrorAction SilentlyContinue |
  ForEach-Object {
    Write-Host $_.TimeCreated
    Write-Host ($_.Message -replace "`r`n", ' ' | ForEach-Object { $_.Substring(0, [Math]::Min(600, $_.Length)) })
    Write-Host '---'
  }
