$content = Get-Content F:\rawrxd\deep2_preprocessed.i
$lineNum = 0
foreach ($line in $content) {
    $lineNum++
    if ($line -match '^namespace Deep2') {
        Write-Host "$lineNum:`t$line"
    }
}