Import-Module 'F:\rawrxd\tools\uia\RawrXD.UIA.psm1' -Force
$s=Start-RawrSession -Exe 'F:\rawrxd\build_ide\bin\RawrXD-Win32IDE-Native.exe' -Sha256 'B54422C4E082D19BEEB46E135FBE5D37D9AD9D202D87321C1B1BA3D326493909' -EvidenceDir 'F:\rawrxd\evidence\T05_ENUM'
Start-Sleep -Seconds 5
Write-Host "=== All controls with AutomationId ==="
Get-RawrControlTree -Session $s -Max 500 | Where-Object { $_.AutomationId } | Select-Object AutomationId, Name, Class, Type, Enabled | Format-Table -AutoSize -Wrap