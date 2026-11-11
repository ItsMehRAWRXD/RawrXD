Get-Volume | Where-Object { $_.DriveLetter -eq 'B' } | Select-Object DriveLetter, FileSystem, FileSystemLabel, @{N='Size_MB';E={[math]::Round($_.Size/1MB,2)}} | Format-Table -AutoSize
Get-ChildItem B:\ -ErrorAction SilentlyContinue | Select-Object Name, Length | Format-Table -AutoSize
