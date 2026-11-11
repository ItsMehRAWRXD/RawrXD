$content = Get-Content F:\rawrxd\tests\CMakeLists.txt -Raw
$content = $content.Replace('/MDd', '$<$<BOOL:${BUILD_SHARED_LIBS}>:/MDd>$<$<NOT:$<BOOL:${BUILD_SHARED_LIBS}>>:/MTd>')
$content = $content.Replace('/MD>', '$<$<BOOL:${BUILD_SHARED_LIBS}>:/MD>$<$<NOT:$<BOOL:${BUILD_SHARED_LIBS}>>:/MT>')
Set-Content F:\rawrxd\tests\CMakeLists.txt $content
Write-Host 'Done'