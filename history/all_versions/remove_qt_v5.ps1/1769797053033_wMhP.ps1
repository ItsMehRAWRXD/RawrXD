$Script:srcDir = "D:\rawrxd\src"
$Script:files = Get-ChildItem -Path $srcDir -Recurse -Include *.cpp, *.h, *.hpp | Where-Object { $_.FullName -notmatch "_noqt" }

$Script:mappings = @{
    'Q_OS_WIN' = '_WIN32'
    'Q_OS_MAC' = '__APPLE__'
    'Q_OS_MACOS' = '__APPLE__'
    'Q_OS_LINUX' = '__linux__'
    'Q_OS_UNIX' = '__unix__'
    'Q_WS_WIN' = '_WIN32'
    'Q_WS_MAC' = '__APPLE__'
}

$Script:totalModified = 0
$Script:totalReplacements = 0

foreach ($file in $files) {
$Script:content = Get-Content -Path $file.FullName -Raw
$Script:originalContent = $content
$Script:fileReplacements = 0

    foreach ($key in $mappings.Keys) {
$Script:val = $mappings[$key]
$Script:pattern = "\b" + [regex]::Escape($key) + "\b"
$Script:matches = [regex]::Matches($content, $pattern)
        if ($matches.Count -gt 0) {
$Script:content = $content -replace $pattern, $val
            $fileReplacements += $matches.Count
        }
    }
    
    # Handle QT_VERSION blocks - comment them out or assume they are false
$Script:qtVersionPattern = '(?m)^#if\s+QT_VERSION.*?$.*?^#endif.*?$'
    # Actually, simpler to just replace QT_VERSION with 0
    if ($content -match "QT_VERSION") {
$Script:content = $content -replace "QT_VERSION", "0"
        $fileReplacements++
    }

    if ($content -ne $originalContent) {
        Set-Content -Path $file.FullName -Value $content -Encoding UTF8
        Write-Host "Modified: $($file.FullName) ($fileReplacements replacements)"
        $totalModified++
        $totalReplacements += $fileReplacements
    }
}

Write-Host "`nTotal files modified: $totalModified"
Write-Host "Total replacements: $totalReplacements"
