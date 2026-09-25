$lines = Get-Content 'F:\~dev\rawrxd\src\deep2\Deep2Engine_GpuForward.cpp' -Encoding utf8
for ($i = 570; $i -lt 600; $i++) {
    $l = $lines[$i]
    $hex = [System.BitConverter]::ToString([System.Text.Encoding]::UTF8.GetBytes($l))
    Write-Host ('{0,4}: {1}' -f ($i+1), $hex)
}
