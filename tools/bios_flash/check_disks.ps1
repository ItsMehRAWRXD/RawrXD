Get-Disk | Where-Object { $_.BusType -eq 'SATA' -or $_.BusType -eq 'NVMe' } | Select-Object Number, FriendlyName, BusType, PartitionStyle, @{N='Size_GB';E={[math]::Round($_.Size/1GB,2)}} | Format-Table -AutoSize
Write-Host "`n=== Current Volumes ==="
Get-Volume | Where-Object { $_.DriveLetter -match '[A-Z]' } | Select-Object DriveLetter, FileSystem, FileSystemLabel, @{N='Free_GB';E={[math]::Round($_.SizeRemaining/1GB,2)}}, @{N='Total_GB';E={[math]::Round($_.Size/1GB,2)}} | Format-Table -AutoSize
Write-Host "`n=== Disk Partitions ==="
Get-Partition | Select-Object DiskNumber, PartitionNumber, DriveLetter, Type, @{N='Size_GB';E={[math]::Round($_.Size/1GB,2)}} | Format-Table -AutoSize
