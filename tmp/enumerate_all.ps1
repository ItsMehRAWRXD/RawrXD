Import-Module "F:\rawrxd\tools\uia\RawrXD.UIA.psm1" -Force
$s = Start-RawrSession -Exe 'F:\rawrxd\build_t080\bin\RawrXD-Win32IDE-Native.exe' -Sha256 'E198F94CF4FFAEC320840C36CE4E4A33A5234E929761A2BA71F7C1C64DD25290' -EvidenceDir 'F:\rawrxd\evidence\T080_ENUM'
Start-Sleep -Seconds 5
Write-Host "=== ALL CONTROLS ==="
$all = Get-RawrControlTree $s -Max 2000
$all | Where-Object { $_.AutomationId -or $_.Name -or $_.Class } | Select-Object AutomationId, Name, Class, Type, Enabled | Format-Table -AutoSize -Wrap