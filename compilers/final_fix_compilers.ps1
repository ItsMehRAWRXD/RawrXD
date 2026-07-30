# Final comprehensive fix for all compiler stubs
$baseDir = "D:\rawrxd\compilers\all_69"
$fixedCount = 0

Get-ChildItem -Path $baseDir -Filter "*.asm" | ForEach-Object {
    $fullPath = $_.FullName
    $content = Get-Content $fullPath -Raw
    $originalContent = $content
    
    # Pattern 1: "Language v1.0" initialized" -> "Language v1.0 initialized"
    $content = $content -replace '"([^"]+ v1\.0)" initialized"', '"$1 initialized"'
    
    # Pattern 2: "Language v1.0" operational" -> "Language v1.0 operational"
    $content = $content -replace '"([^"]+ v1\.0)" operational"', '"$1 operational"'
    
    # Pattern 3: "Language v1.0" v" -> "Language v1.0"
    $content = $content -replace '"([^"]+ v1\.0)" v"', '"$1"'
    
    # Pattern 4: "Language" "v1.0" -> "Language v1.0"
    $content = $content -replace '"([^"]+)" "v1\.0"', '"$1 v1.0"'
    
    # Pattern 5: "Language" "1.0" -> "Language v1.0"
    $content = $content -replace '"([^"]+)" "1\.0"', '"$1 v1.0"'
    
    # Pattern 6: "Language" "1.0"" -> "Language v1.0"
    $content = $content -replace '"([^"]+)" "1\.0""', '"$1 v1.0"'
    
    # Pattern 7: "Language" "1.0"" v" -> "Language v1.0"
    $content = $content -replace '"([^"]+)" "1\.0"" v"', '"$1 v1.0"'
    
    # Pattern 8: "[READY] "Language... -> "[READY] Language...
    $content = $content -replace '"\[READY\] "([^"]+)"', '"[READY] $1"'
    
    # Pattern 9: "[TEST] PASS - "Language... -> "[TEST] PASS - Language...
    $content = $content -replace '"\[TEST\] PASS - "([^"]+)"', '"[TEST] PASS - $1"'
    
    # Pattern 10: "Language" "1.0"" initialized" -> "Language v1.0 initialized"
    $content = $content -replace '"([^"]+)" "1\.0"" initialized"', '"$1 v1.0 initialized"'
    
    # Pattern 11: "Language" "1.0"" operational" -> "Language v1.0 operational"
    $content = $content -replace '"([^"]+)" "1\.0"" operational"', '"$1 v1.0 operational"'
    
    if ($content -ne $originalContent) {
        Set-Content $fullPath $content -NoNewline
        Write-Host "Fixed: $($_.Name)"
        $fixedCount++
    }
}

Write-Host "`nFixed $fixedCount files"
