# chocolateyuninstall.ps1
# Phase H.2 Batch 2/5: Chocolatey Uninstallation Script

$ErrorActionPreference = 'Stop'

$packageName = 'rawrxd'
$softwareName = 'RawrXD Sovereign'
$installerType = 'MSI'

$silentArgs = '/qn /norestart'
$validExitCodes = @(0, 3010, 1605, 1614, 1641)

$uninstalled = $false

[array]$key = Get-UninstallRegistryKey -SoftwareName $softwareName

if ($key.Count -eq 1) {
  $key | ForEach-Object {
    $file = $_.UninstallString

    if ($installerType -eq 'MSI') {
      $silentArgs = "$($_.PSChildName) $silentArgs"
      $file = ''
    }

    Uninstall-ChocolateyPackage -PackageName $packageName `
                                -FileType $installerType `
                                -SilentArgs "$silentArgs" `
                                -ValidExitCodes $validExitCodes `
                                -File "$file"
  }
} elseif ($key.Count -eq 0) {
  Write-Warning "$packageName has already been uninstalled by other means."
} elseif ($key.Count -gt 1) {
  Write-Warning "$($key.Count) matches found!"
  Write-Warning "To prevent accidental data loss, no programs will be uninstalled."
  Write-Warning "Please alert package maintainer the following keys were matched:"
  $key | ForEach-Object { Write-Warning "- $($_.DisplayName)" }
}

# Remove from PATH
$installPath = "${env:ProgramFiles}\RawrXD"
$currentPath = [Environment]::GetEnvironmentVariable('Path', 'Machine')
if ($currentPath -like "*$installPath*") {
    $newPath = $currentPath -replace [regex]::Escape(";$installPath"), ''
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'Machine')
    Write-Host "Removed RawrXD from system PATH" -ForegroundColor Green
}

Write-Host "RawrXD Sovereign uninstalled successfully" -ForegroundColor Green
