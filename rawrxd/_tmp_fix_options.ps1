$content = Get-Content 'f:\~dev\rawrxd\CMakeLists.txt'
$content = $content -replace '(BUILD_DEEP2_[^)]+)\s+ON\)', '$1 OFF)'
$content | Set-Content 'f:\~dev\rawrxd\CMakeLists.txt'
Write-Host "Done. Replaced $(($content | Select-String 'BUILD_DEEP2_' | Measure-Object).Count) occurrences."
