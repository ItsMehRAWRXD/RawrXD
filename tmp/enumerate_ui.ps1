Import-Module 'F:\rawrxd\tools\uia\RawrXD.UIA.psm1' -Force
$s = Start-RawrSession -Exe 'F:\rawrxd\build_t080\bin\RawrXD-Win32IDE-Native.exe' -Sha256 'E198F94CF4FFAEC320840C36CE4E4A33A5234E929761A2BA71F7C1C64DD25290' -EvidenceDir 'F:\rawrxd\evidence\T080_UIA_ENUM'
Start-Sleep -Seconds 3
$tree = Get-RawrControlTree -Session $s -Max 2000
$tree | Where-Object { $_.Type -or $_.Name -or $_.AutomationId } | Select-Object Name, AutomationId, Class, Type, Enabled | Format-Table -AutoSize -Wrap