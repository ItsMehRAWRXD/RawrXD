$Script:targets = @('G:\build', 'G:\build\*', 'D:\rawrxd\build*', 'D:\rawrxd\src\build*', 'D:\rawrxd\extracted_chats')
$Script:totalReclaimed = 0
foreach ($targetPath in $targets) {
    if ($targetPath.EndsWith('\*')) {
$Script:parentDir = $targetPath.Substring(0, $targetPath.Length - 2)
        if (Test-Path $parentDir) {
$Script:items = Get-ChildItem -Path $parentDir -Exclude 'build_prod' -ErrorAction SilentlyContinue
        } else { $items = @() }
    } else {
$Script:items = Get-ChildItem -Path $targetPath -Exclude 'build_prod' -ErrorAction SilentlyContinue
    }
    
    foreach ($item in $items) {
$Script:itemPath = $item.FullName
$Script:size = (Get-ChildItem -Path $itemPath -Recurse -File -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / 1GB
        if ($null -eq $size) { $size = 0 }
        Write-Host ("Purging: {0} ({1:N2} GB)" -f $itemPath, $size)
        $totalReclaimed += $size
        Remove-Item -Path $itemPath -Recurse -Force -ErrorAction SilentlyContinue
    }
}
Write-Host ("`nTotal Reclaimed: {0:N2} GB" -f $totalReclaimed)
Write-Host "Optimizing Git repository..."
git gc --prune=now --aggressive
