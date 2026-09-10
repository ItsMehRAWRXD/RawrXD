$inf = 'C:\Users\Garrett\AppData\Local\Microsoft\WinGet\Packages\VirtualDrivers.Virtual-Display-Driver_Microsoft.Winget.Source_8wekyb3d8bbwe\SignedDrivers\x86\VDD\MttVDD.inf'
$devcon = 'C:\Users\Garrett\AppData\Local\Microsoft\WinGet\Packages\VirtualDrivers.Virtual-Display-Driver_Microsoft.Winget.Source_8wekyb3d8bbwe\Dependencies\devcon.exe'
$log = 'G:\~dev\rawrxd\evidence\RAWRXD_PERFORMANCE_001\G3_GPU1_AMDVLK_UNBLOCK_001\P2d_VDD\install_admin.txt'
New-Item -ItemType Directory -Force -Path (Split-Path $log) | Out-Null
$r = @()
$r += "ASOF=$(Get-Date -Format o)"
$r += (pnputil /add-driver $inf /install 2>&1 | Out-String)
$r += (& $devcon install $inf Root\MttVDD 2>&1 | Out-String)
$r += (Get-PnpDevice | Where-Object { $_.FriendlyName -match 'Virtual Display|MttVDD' } | Format-List | Out-String)
$r | Set-Content $log