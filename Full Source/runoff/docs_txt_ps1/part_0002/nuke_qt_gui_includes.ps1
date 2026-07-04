$Script:srcDir = "D:\rawrxd\src"
$Script:files = Get-ChildItem -Path $srcDir -Recurse -Include *.cpp, *.h, *.hpp

$Script:qtIncludes = @(
    '#include <QApplication>',
    '#include <QWidget>',
    '#include <QMainWindow>',
    '#include <QDialog>',
    '#include <QTextEdit>',
    '#include <QLineEdit>',
    '#include <QClipboard>',
    '#include <QPushButton>',
    '#include <QLabel>',
    '#include <QVBoxLayout>',
    '#include <QHBoxLayout>',
    '#include <QComboBox>',
    '#include <QCheckBox>',
    '#include <QSpinBox>',
    '#include <QSlider>',
    '#include <QProgressBar>',
    '#include <QTreeView>',
    '#include <QListView>',
    '#include <QTableView>'
)

$Script:totalModified = 0
$Script:totalRemoved = 0

foreach ($file in $files) {
$Script:content = Get-Content -Path $file.FullName -Raw
    if (-not $content) { continue }
    
$Script:originalContent = $content
$Script:fileRemovals = 0
    
    foreach ($include in $qtIncludes) {
$Script:pattern = [regex]::Escape($include)
$Script:matches = [regex]::Matches($content, "(?m)^$pattern\s*$")
        if ($matches.Count -gt 0) {
$Script:content = $content -replace "(?m)^$pattern\s*$", ''
            $fileRemovals += $matches.Count
        }
    }
    
    # Also remove forward declarations like "class QWidget;"
$Script:content = $content -replace '(?m)^\s*class\s+Q[A-Z]\w+;\s*$', ''
    
    # Remove QApplication usage patterns
$Script:content = $content -replace 'QApplication::clipboard\(\)', 'nullptr'
$Script:content = $content -replace 'QApplication::processEvents\(\)', '// processEvents()'
$Script:content = $content -replace 'QApplication::instance\(\)', 'nullptr'
    
    if ($content -ne $originalContent) {
        Set-Content -Path $file.FullName -Value $content -Encoding UTF8
        Write-Host "Cleaned: $($file.Name) ($fileRemovals removals)"
        $totalModified++
        $totalRemoved += $fileRemovals
    }
}

Write-Host ""
Write-Host "Total files cleaned: $totalModified" -ForegroundColor Green
Write-Host "Total Qt includes removed: $totalRemoved" -ForegroundColor Green
