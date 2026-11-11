# Fix malformed string patterns in compiler stubs
$baseDir = "D:\rawrxd\compilers\all_69"
$fixedCount = 0

Get-ChildItem -Path $baseDir -Filter "*.asm" | ForEach-Object {
    $fullPath = $_.FullName
    $content = Get-Content $fullPath -Raw
    $originalContent = $content
    
    # Fix pattern: "Language Compiler v1.0" v" -> "Language Compiler v1.0"
    $content = $content -replace '"([^"]+)" v"', '"$1"'
    
    # Fix pattern: "[READY] "Language ..." -> "[READY] Language ..."
    $content = $content -replace '"\[READY\] "([^"]+)"', '"[READY] $1"'
    
    # Fix pattern: "[TEST] PASS - "Language ..." -> "[TEST] PASS - Language ..."
    $content = $content -replace '"\[TEST\] PASS - "([^"]+)"', '"[TEST] PASS - $1"'
    
    # Fix pattern: "Language" "1.0"" -> "Language v1.0"
    $content = $content -replace '"([^"]+)" "1\.0""', '"$1 v1.0"'
    
    # Fix pattern: "Language" "1.0" -> "Language v1.0"
    $content = $content -replace '"([^"]+)" "1\.0"', '"$1 v1.0"'
    
    if ($content -ne $originalContent) {
        Set-Content $fullPath $content -NoNewline
        Write-Host "Fixed malformed strings: $($_.Name)"
        $fixedCount++
    }
}

Write-Host "`nFixed $fixedCount files with malformed strings"
