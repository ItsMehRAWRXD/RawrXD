# Use diskpart to list volumes and find EFI partition
$diskpartScript = @"
list disk
list volume
list partition
exit
"@

$diskpartScript | diskpart | Out-String | Write-Host

# Try to find EFI partition using bcdedit
Write-Host "`n=== BCD Boot Entries ==="
bcdedit /enum firmware | Out-String | Write-Host

# Check if we can see EFI partition with mountvol
Write-Host "`n=== Volume GUIDs ==="
mountvol | Where-Object { $_ -match '\\?\Volume' } | ForEach-Object { Write-Host $_ }
