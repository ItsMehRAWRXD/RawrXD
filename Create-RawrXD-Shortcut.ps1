#Requires -Version 5.1
<#
.SYNOPSIS
    Create desktop shortcut for RawrXD Agentic EXE
#>

$exePath = 'C:\Users\HiH8e\OneDrive\Desktop\Powershield\RawrXD-Agentic.exe'
$shortcutPath = [System.IO.Path]::Combine([Environment]::GetFolderPath('Desktop'), 'RawrXD-Agentic.lnk')

$WshShell = New-Object -ComObject WScript.Shell
$shortcut = $WshShell.CreateShortcut($shortcutPath)
$shortcut.TargetPath = $exePath
$shortcut.IconLocation = $exePath
$shortcut.Description = "RawrXD IDE with Agentic Code Generation"
$shortcut.Save()

Write-Host "✅ Shortcut created on desktop!" -ForegroundColor Green
Write-Host "   Location: $shortcutPath" -ForegroundColor Cyan
