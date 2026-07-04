$Script:srcDir = "D:\rawrxd\src"
$Script:files = Get-ChildItem -Path $srcDir -Recurse -Include *.cpp, *.h, *.hpp | Where-Object { $_.FullName -notmatch "_noqt" }

$Script:mappings = @{
    'Q_UNUSED' = '(void)'
    'Q_ASSERT' = 'assert'
    'Q_PROPERTY' = '// Q_PROPERTY'
    'Q_ENUM' = '// Q_ENUM'
    'Q_OBJECT' = ''
    'Q_SIGNALS' = 'public:'
    'Q_SLOTS' = 'public:'
    'Q_DECLARE_METATYPE' = '// Q_DECLARE_METATYPE'
    'Q_FOREACH' = 'for'
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

    if ($content -ne $originalContent) {
        Set-Content -Path $file.FullName -Value $content -Encoding UTF8
        Write-Host "Modified: $($file.FullName) ($fileReplacements replacements)"
        $totalModified++
        $totalReplacements += $fileReplacements
    }
}

Write-Host "`nTotal files modified: $totalModified"
Write-Host "Total replacements: $totalReplacements"
