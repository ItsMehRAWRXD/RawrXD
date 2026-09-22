$base = 'F:\~dev\rawrxd_recovery_20260922'
New-Item -ItemType Directory -Path $base -Force | Out-Null

# Manifest for F tree
Write-Output 'Generating F manifest...'
$fFiles = Get-ChildItem -Path 'F:\~dev\rawrxd' -Recurse -File | Select-Object FullName, Length, LastWriteTime
$fResult = foreach ($f in $fFiles) {
    $rel = $f.FullName.Substring('F:\~dev\rawrxd'.Length).TrimStart('\')
    $sha = try { (Get-FileHash $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch { 'ERROR' }
    [PSCustomObject]@{
        RelativePath = $rel
        Size = $f.Length
        SHA256 = $sha
        LastWriteTime = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
    }
}
$fResult | Export-Csv -Path "$base\manifest_f.csv" -NoTypeInformation
Write-Output "F manifest: $($fResult.Count) files"

# Manifest for G tree
Write-Output 'Generating G manifest...'
$gFiles = Get-ChildItem -Path 'G:\~dev\rawrxd' -Recurse -File | Select-Object FullName, Length, LastWriteTime
$gResult = foreach ($f in $gFiles) {
    $rel = $f.FullName.Substring('G:\~dev\rawrxd'.Length).TrimStart('\')
    $sha = try { (Get-FileHash $f.FullName -Algorithm SHA256 -ErrorAction Stop).Hash } catch { 'ERROR' }
    [PSCustomObject]@{
        RelativePath = $rel
        Size = $f.Length
        SHA256 = $sha
        LastWriteTime = $f.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss')
    }
}
$gResult | Export-Csv -Path "$base\manifest_g.csv" -NoTypeInformation
Write-Output "G manifest: $($gResult.Count) files"
Write-Output 'Done.'
