# Create a small FAT32 VHD for BIOS flashing
# This VHD can be mounted in Windows and also seen by ASUS EZ Flash 3

$vhdPath = "D:\\rawrxd\\tools\\bios_flash\\bios_flash.vhd"
$vhdSizeMB = 100
$driveLetter = "B"

Write-Host "Creating VHD at $vhdPath ..."

# Create VHD using diskpart
$diskpartScript = @"
create vdisk file="$vhdPath" maximum=$vhdSizeMB type=fixed
select vdisk file="$vhdPath"
attach vdisk
convert mbr
create partition primary size=$vhdSizeMB
format fs=fat32 quick label="BIOFLASH"
assign letter=$driveLetter
exit
"@

$diskpartScript | diskpart

Write-Host "`nVHD created and mounted as $driveLetter`:"
Write-Host "Copy TGB650PW.CAP to ${driveLetter}:\\"

# Verify
Get-Volume -DriveLetter $driveLetter | Select-Object DriveLetter, FileSystem, FileSystemLabel, @{N='Size_MB';E={[math]::Round($_.Size/1MB,2)}}, @{N='Free_MB';E={[math]::Round($_.SizeRemaining/1MB,2)}} | Format-Table -AutoSize
