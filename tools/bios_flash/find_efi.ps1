# Find boot disk and EFI partition
$bootConfig = Get-CimInstance Win32_BootConfiguration
Write-Host "Boot Directory: $($bootConfig.BootDirectory)"
Write-Host "Caption: $($bootConfig.Caption)"

Write-Host "`n=== Boot/EFI Partitions ==="
Get-Partition | Where-Object { $_.IsBoot -eq $true -or $_.Type -eq 'System' -or $_.Type -eq 'Reserved' -or $_.IsActive -eq $true } | 
    Select-Object DiskNumber, PartitionNumber, DriveLetter, Type, @{N='Size_MB';E={[math]::Round($_.Size/1MB,2)}}, IsBoot, IsActive | 
    Format-Table -AutoSize

Write-Host "`n=== All Disks ==="
Get-Disk | Select-Object Number, FriendlyName, BusType, PartitionStyle, @{N='Size_GB';E={[math]::Round($_.Size/1GB,2)}} | Format-Table -AutoSize

Write-Host "`n=== C: Drive Disk ==="
$cdisk = Get-Partition | Where-Object { $_.DriveLetter -eq 'C' }
if ($cdisk) {
    Write-Host "C: is on Disk $($cdisk.DiskNumber), Partition $($cdisk.PartitionNumber)"
}
