# Load Storage module
Import-Module Storage -ErrorAction SilentlyContinue

# Get all disks
Write-Host "=== All Disks ==="
Get-Disk | Select-Object Number, FriendlyName, BusType, PartitionStyle, @{N='Size_GB';E={[math]::Round($_.Size/1GB,2)}}, @{N='Allocated_GB';E={[math]::Round($_.AllocatedSize/1GB,2)}}, @{N='Unallocated_GB';E={[math]::Round(($_.Size - $_.AllocatedSize)/1GB,2)}} | Format-Table -AutoSize

# Get partitions with disk numbers
Write-Host "`n=== Partitions ==="
Get-Partition | Select-Object DiskNumber, PartitionNumber, DriveLetter, Type, @{N='Size_GB';E={[math]::Round($_.Size/1GB,2)}}, IsActive, IsBoot | Format-Table -AutoSize

# Get volumes
Write-Host "`n=== Volumes ==="
Get-Volume | Where-Object { $_.DriveLetter -match '[A-Z]' -or $_.FileSystemLabel } | Select-Object DriveLetter, FileSystem, FileSystemLabel, @{N='Free_GB';E={[math]::Round($_.SizeRemaining/1GB,2)}}, @{N='Total_GB';E={[math]::Round($_.Size/1GB,2)}} | Format-Table -AutoSize

# Check for EFI partition
Write-Host "`n=== EFI System Partition ==="
Get-Partition | Where-Object { $_.Type -eq 'System' } | Select-Object DiskNumber, PartitionNumber, DriveLetter, Type, @{N='Size_MB';E={[math]::Round($_.Size/1MB,2)}} | Format-Table -AutoSize
