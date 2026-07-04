$Script:srcDir = "D:\rawrxd\src"
$Script:files = Get-ChildItem -Path $srcDir -Recurse -Include *.cpp, *.h, *.hpp

# Patterns to remove or comment out
$Script:removalPatterns = @(
    '(?m)^\s*\*\s*memory_logger.*?$',
    '(?m)^\s*\*\s*perf_logger.*?$',
    'device->memory_logger->.*?;',
    'device->perf_logger->.*?;',
    'ctx->device->memory_logger->.*?;',
    'ctx->device->perf_logger->.*?;',
    'buf->device->memory_logger->.*?;',
    'buf->device->perf_logger->.*?;',
    'm_logger->.*?;',
    'logger_->.*?;',
    '(?m)^\s*Logger\*\s+m_logger.*?;',
    '(?m)^\s*Logger\*\s+logger_.*?;',
    '(?m)^\s*Logger\*\s+m_logger\s*=.*?;',
)

$Script:totalModified = 0
$Script:totalReplacements = 0

foreach ($file in $files) {
$Script:content = Get-Content -Path $file.FullName -Raw
$Script:originalContent = $content
$Script:fileReplacements = 0

    foreach ($pattern in $removalPatterns) {
$Script:matches = [regex]::Matches($content, $pattern)
        if ($matches.Count -gt 0) {
$Script:content = $content -replace $pattern, ''
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
