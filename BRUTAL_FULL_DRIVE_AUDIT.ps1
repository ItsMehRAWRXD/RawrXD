# BRUTAL_FULL_DRIVE_AUDIT.ps1
# Comprehensive analysis of D: drive - NO SHINE BOX, JUST BRUTAL TRUTH
# Finds: REAL code vs STUBS vs SCAFFOLDING vs MISSING

param(
    [string]$RootPath = "D:\",
    [string]$OutputFile = "brutal_audit_report.html",
    [switch]$IncludeNodeModules,
    [switch]$IncludeGit
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "Continue"

Write-Host ""
Write-Host "========================================" -ForegroundColor Red
Write-Host "🔥 BRUTAL FULL DRIVE AUDIT" -ForegroundColor Red
Write-Host "NO SHINE BOX - JUST BRUTAL TRUTH" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Red
Write-Host ""
Write-Host "Scanning: $RootPath" -ForegroundColor Yellow
Write-Host "This will take a while..." -ForegroundColor Gray
Write-Host ""

# Statistics
$Stats = @{
    TotalFiles = 0
    TotalLines = 0
    RealFiles = 0
    StubFiles = 0
    ScaffoldFiles = 0
    EmptyFiles = 0
    MissingDocs = 0
    StartTime = Get-Date
}

# File categories
$Categories = @{
    "Native Toolchain" = @("*.exe", "*.dll", "*.lib", "*.obj", "*.asm", "*.c", "*.cpp", "*.h")
    "Scripts" = @("*.ps1", "*.bat", "*.cmd", "*.sh", "*.py", "*.js", "*.ts")
    "Documentation" = @("*.md", "*.txt", "*.rst", "*.doc", "*.docx")
    "Config" = @("*.json", "*.xml", "*.yaml", "*.yml", "*.ini", "*.cfg")
    "Build" = @("CMakeLists.txt", "*.cmake", "Makefile", "*.ninja", "*.vcxproj", "*.sln")
}

# Patterns that indicate REAL implementation
$RealPatterns = @(
    "int main\s*\(",
    "WINAPI",
    "CreateFile",
    "ReadFile",
    "WriteFile",
    "VirtualAlloc",
    "malloc\s*\(",
    "free\s*\(",
    "new\s+\w+",
    "class\s+\w+",
    "struct\s+\w+",
    "function\s+\w+",
    "def\s+\w+",
    "sub\s+\w+",
    "Write-Host",
    "Write-Output",
    "echo\s+",
    "printf\s*\(",
    "cout\s*<<",
    "std::",
    "import\s+",
    "from\s+\w+\s+import",
    "require\s*\(",
    "module\.exports",
    "export\s+default",
    "public\s+static",
    "private\s+void",
    "protected\s+",
    "try\s*{",
    "catch\s*\(",
    "finally\s*{",
    "if\s*\(.+\)\s*{",
    "for\s*\(.+\)\s*{",
    "while\s*\(.+\)\s*{",
    "switch\s*\(.+\)",
    "case\s+\w+",
    "return\s+",
    "break\s*;",
    "continue\s*;",
    "throw\s+new",
    "async\s+function",
    "await\s+",
    "Promise\s*\(",
    "\.then\s*\(",
    "\.catch\s*\(",
    "\.finally\s*\("
)

# Patterns that indicate STUB/SCAFFOLDING
$StubPatterns = @(
    "//\s*TODO",
    "//\s*FIXME",
    "//\s*XXX",
    "//\s*STUB",
    "//\s*stub",
    "//\s*Not\s+implemented",
    "//\s*Not\s+yet\s+implemented",
    "//\s*Placeholder",
    "//\s*Coming\s+soon",
    "//\s*Under\s+construction",
    "//\s*Incomplete",
    "//\s*Draft",
    "//\s*Prototype",
    "//\s*Temporary",
    "//\s*HACK",
    "TODO:\s*Implement",
    "FIXME:\s*Implement",
    "return\s+0\s*;\s*//",
    "return\s+false\s*;\s*//",
    "return\s+true\s*;\s*//",
    "return\s+null\s*;\s*//",
    "return\s+nullptr\s*;\s*//",
    "throw\s+new\s+NotImplementedException",
    "throw.*Not\s+implemented",
    "printf.*STUB",
    "console\.log.*STUB",
    "Write-Host.*STUB",
    "pass.*TODO",
    "#.*TODO",
    "#.*FIXME",
    "#.*XXX",
    "#.*Not\s+implemented"
)

# Patterns that indicate SCAFFOLDING (headers, empty implementations)
$ScaffoldPatterns = @(
    "//\s*TODO:\s*Add\s+implementation",
    "//\s*TODO:\s*Fill\s+in",
    "//\s*TODO:\s*Complete",
    "//\s*TODO:\s*Write",
    "//\s*TODO:\s*Implement",
    "//\s*@todo",
    "//\s*@TODO",
    "//\s*WIP",
    "//\s*Work\s+in\s+progress",
    "//\s*Skeleton",
    "//\s*Template",
    "//\s*Boilerplate",
    "//\s*Generated",
    "//\s*Auto-generated",
    "//\s*Auto\s+generated",
    "//\s*This\s+is\s+a\s+generated\s+file",
    "//\s*DO\s+NOT\s+EDIT",
    "//\s*Edit\s+at\s+your\s+own\s+risk",
    "//\s*Implementation\s+TBD",
    "//\s*To\s+be\s+implemented",
    "//\s*Future\s+work",
    "//\s*Pending",
    "//\s*Deferred",
    "//\s*On\s+hold",
    "//\s*Backlog",
    "//\s*Planned",
    "//\s*Proposed",
    "//\s*Idea",
    "//\s*Concept",
    "//\s*Design",
    "//\s*Spec",
    "//\s*Specification"
)

# Excluded directories
$ExcludedDirs = @(
    "node_modules",
    ".git",
    "build",
    "bin",
    "obj",
    ".vs",
    ".vscode",
    "__pycache__",
    "vendor",
    "third_party",
    "3rdparty",
    "archive",
    ".archive",
    "backups",
    ".backups",
    "temp",
    ".temp",
    "tmp",
    ".tmp",
    "cache",
    ".cache",
    "logs",
    ".logs",
    "output",
    "dist",
    "release",
    "debug"
)

if ($IncludeNodeModules) { $ExcludedDirs = $ExcludedDirs | Where-Object { $_ -ne "node_modules" } }
if ($IncludeGit) { $ExcludedDirs = $ExcludedDirs | Where-Object { $_ -ne ".git" } }

# Results storage
$Results = @()

# Scan function
function Scan-File {
    param([string]$FilePath)
    
    try {
        $fileInfo = Get-Item $FilePath -ErrorAction SilentlyContinue
        if (-not $fileInfo) { return }
        
        # Skip excluded directories
        foreach ($excluded in $ExcludedDirs) {
            if ($FilePath -like "*\$excluded\*") { return }
        }
        
        # Skip large files (>10MB)
        if ($fileInfo.Length -gt 10MB) { return }
        
        # Skip binary files
        $binaryExts = @('.exe', '.dll', '.lib', '.obj', '.pdb', '.ilk', '.exp', '.bin', '.dat', '.db', '.sqlite', '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.ico', '.zip', '.7z', '.rar', '.gz', '.tar', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx')
        if ($binaryExts -contains $fileInfo.Extension.ToLower()) {
            return
        }
        
        # Read file content
        $content = Get-Content $FilePath -Raw -ErrorAction SilentlyContinue
        if (-not $content) { return }
        
        $lines = ($content -split "`n").Count
        $size = $fileInfo.Length
        
        # Determine category
        $category = "Other"
        foreach ($cat in $Categories.Keys) {
            $patterns = $Categories[$cat]
            foreach ($pattern in $patterns) {
                if ($fileInfo.Name -like $pattern) {
                    $category = $cat
                    break
                }
            }
            if ($category -ne "Other") { break }
        }
        
        # Analyze content
        $isReal = $false
        $isStub = $false
        $isScaffold = $false
        $realCodeCount = 0
        $stubCodeCount = 0
        $scaffoldCodeCount = 0
        
        # Check for real code
        foreach ($pattern in $RealPatterns) {
            $matches = [regex]::Matches($content, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            $realCodeCount += $matches.Count
            if ($matches.Count -gt 0) { $isReal = $true }
        }
        
        # Check for stubs
        foreach ($pattern in $StubPatterns) {
            $matches = [regex]::Matches($content, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            $stubCodeCount += $matches.Count
            if ($matches.Count -gt 0) { $isStub = $true }
        }
        
        # Check for scaffolding
        foreach ($pattern in $ScaffoldPatterns) {
            $matches = [regex]::Matches($content, $pattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
            $scaffoldCodeCount += $matches.Count
            if ($matches.Count -gt 0) { $isScaffold = $true }
        }
        
        # Determine status
        $status = "UNKNOWN"
        if ($isStub) {
            $status = "STUB"
        } elseif ($isScaffold -and -not $isReal) {
            $status = "SCAFFOLD"
        } elseif ($isReal -and $isScaffold) {
            $status = "PARTIAL"
        } elseif ($isReal) {
            $status = "REAL"
        } elseif ($lines -lt 5) {
            $status = "EMPTY"
        }
        
        # Update stats
        $script:Stats.TotalFiles++
        $script:Stats.TotalLines += $lines
        
        switch ($status) {
            "REAL" { $script:Stats.RealFiles++ }
            "STUB" { $script:Stats.StubFiles++ }
            "SCAFFOLD" { $script:Stats.ScaffoldFiles++ }
            "EMPTY" { $script:Stats.EmptyFiles++ }
        }
        
        # Store result
        $result = [PSCustomObject]@{
            File = $fileInfo.Name
            Path = $FilePath
            Category = $category
            Lines = $lines
            SizeKB = [math]::Round($size / 1024, 2)
            Status = $status
            RealCode = $realCodeCount
            StubCode = $stubCodeCount
            ScaffoldCode = $scaffoldCodeCount
            Extension = $fileInfo.Extension
        }
        
        $script:Results += $result
        
    } catch {
        # Silently continue
    }
}

# Main scan
Write-Host "Scanning files..." -ForegroundColor Yellow

$allFiles = Get-ChildItem -Path $RootPath -Recurse -File -ErrorAction SilentlyContinue | 
    Where-Object { 
        $excluded = $false
        foreach ($excl in $ExcludedDirs) {
            if ($_.FullName -like "*\$excl\*") { $excluded = $true; break }
        }
        -not $excluded
    }

$totalFiles = $allFiles.Count
$currentFile = 0

foreach ($file in $allFiles) {
    $currentFile++
    if ($currentFile % 100 -eq 0) {
        $percent = [math]::Round(($currentFile / $totalFiles) * 100, 1)
        Write-Progress -Activity "Scanning Files" -Status "$percent% Complete" -PercentComplete $percent
    }
    
    Scan-File -FilePath $file.FullName
}

Write-Progress -Activity "Scanning Files" -Completed

# Calculate duration
$endTime = Get-Date
$duration = $endTime - $Stats.StartTime

# Calculate percentages
$realPercent = if ($Stats.TotalFiles -gt 0) { [math]::Round(($Stats.RealFiles / $Stats.TotalFiles) * 100, 1) } else { 0 }
$stubPercent = if ($Stats.TotalFiles -gt 0) { [math]::Round(($Stats.StubFiles / $Stats.TotalFiles) * 100, 1) } else { 0 }
$scaffoldPercent = if ($Stats.TotalFiles -gt 0) { [math]::Round(($Stats.ScaffoldFiles / $Stats.TotalFiles) * 100, 1) } else { 0 }
$emptyPercent = if ($Stats.TotalFiles -gt 0) { [math]::Round(($Stats.EmptyFiles / $Stats.TotalFiles) * 100, 1) } else { 0 }

# Calculate TRUE completion
# REAL = 100%, PARTIAL = 50%, SCAFFOLD = 10%, STUB = 0%, EMPTY = 0%
$trueCompletion = if ($Stats.TotalFiles -gt 0) {
    $realWeight = $Stats.RealFiles * 1.0
    $partialWeight = ($Results | Where-Object { $_.Status -eq "PARTIAL" }).Count * 0.5
    $scaffoldWeight = $Stats.ScaffoldFiles * 0.1
    $stubWeight = $Stats.StubFiles * 0.0
    $emptyWeight = $Stats.EmptyFiles * 0.0
    [math]::Round((($realWeight + $partialWeight + $scaffoldWeight) / $Stats.TotalFiles) * 100, 1)
} else { 0 }

# Console output
Write-Host ""
Write-Host "========================================" -ForegroundColor Red
Write-Host "📊 BRUTAL AUDIT RESULTS" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Red
Write-Host ""
Write-Host "Duration: $($duration.ToString('hh\:mm\:ss'))" -ForegroundColor Gray
Write-Host ""
Write-Host "Files Scanned: $($Stats.TotalFiles)" -ForegroundColor White
Write-Host "Total Lines: $([math]::Round($Stats.TotalLines, 0).ToString('N0'))" -ForegroundColor White
Write-Host ""
Write-Host "REAL Implementation: $realPercent% ($($Stats.RealFiles) files)" -ForegroundColor Green
Write-Host "PARTIAL Implementation: $([math]::Round((($Results | Where-Object { $_.Status -eq "PARTIAL" }).Count / $Stats.TotalFiles) * 100, 1))% (($($Results | Where-Object { $_.Status -eq "PARTIAL" }).Count) files)" -ForegroundColor Yellow
Write-Host "SCAFFOLDING Only: $scaffoldPercent% ($($Stats.ScaffoldFiles) files)" -ForegroundColor Cyan
Write-Host "STUBS: $stubPercent% ($($Stats.StubFiles) files)" -ForegroundColor Red
Write-Host "EMPTY: $emptyPercent% ($($Stats.EmptyFiles) files)" -ForegroundColor Gray
Write-Host ""
Write-Host "========================================" -ForegroundColor Red
Write-Host "🔥 TRUE COMPLETION: $trueCompletion%" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Red
Write-Host ""

# Category breakdown
Write-Host "📂 CATEGORY BREAKDOWN" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Yellow

$categoryGroups = $Results | Group-Object Category | Sort-Object Name
foreach ($group in $categoryGroups) {
    $realInCat = ($group.Group | Where-Object { $_.Status -eq "REAL" }).Count
    $stubInCat = ($group.Group | Where-Object { $_.Status -eq "STUB" }).Count
    $scaffoldInCat = ($group.Group | Where-Object { $_.Status -eq "SCAFFOLD" }).Count
    $partialInCat = ($group.Group | Where-Object { $_.Status -eq "PARTIAL" }).Count
    $totalInCat = $group.Group.Count
    
    $catCompletion = if ($totalInCat -gt 0) {
        [math]::Round((($realInCat + ($partialInCat * 0.5) + ($scaffoldInCat * 0.1)) / $totalInCat) * 100, 1)
    } else { 0 }
    
    $color = if ($catCompletion -ge 80) { "Green" } elseif ($catCompletion -ge 50) { "Yellow" } elseif ($catCompletion -ge 20) { "Cyan" } else { "Red" }
    
    Write-Host "  $($group.Name):" -ForegroundColor White
    Write-Host "    Total: $totalInCat | REAL: $realInCat | PARTIAL: $partialInCat | SCAFFOLD: $scaffoldInCat | STUB: $stubInCat" -ForegroundColor $color
    Write-Host "    TRUE Completion: $catCompletion%" -ForegroundColor $color
}

Write-Host ""

# Top 20 stub files
Write-Host "❌ TOP 20 STUB FILES (Need Implementation)" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Red

$stubFiles = $Results | Where-Object { $_.Status -eq "STUB" } | Sort-Object Lines -Descending | Select-Object -First 20
foreach ($file in $stubFiles) {
    Write-Host "  $($file.File) ($($file.Lines) lines)" -ForegroundColor Red
    Write-Host "    Path: $($file.Path)" -ForegroundColor DarkGray
}

Write-Host ""

# Top 20 scaffold files
Write-Host "⚠️ TOP 20 SCAFFOLD FILES (Need Real Code)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

$scaffoldFiles = $Results | Where-Object { $_.Status -eq "SCAFFOLD" } | Sort-Object Lines -Descending | Select-Object -First 20
foreach ($file in $scaffoldFiles) {
    Write-Host "  $($file.File) ($($file.Lines) lines)" -ForegroundColor Cyan
    Write-Host "    Path: $($file.Path)" -ForegroundColor DarkGray
}

Write-Host ""

# Generate HTML report
$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>BRUTAL AUDIT REPORT - D: Drive</title>
    <style>
        body { font-family: 'Segoe UI', sans-serif; margin: 20px; background: #1a1a1a; color: #fff; }
        h1 { color: #ff4444; border-bottom: 3px solid #ff4444; }
        h2 { color: #ffaa00; margin-top: 30px; }
        .metric { display: inline-block; margin: 10px 20px; padding: 15px; background: #333; border-radius: 8px; }
        .metric-value { font-size: 32px; font-weight: bold; }
        .metric-label { font-size: 12px; color: #aaa; }
        .real { color: #44ff44; }
        .partial { color: #ffaa00; }
        .scaffold { color: #44aaff; }
        .stub { color: #ff4444; }
        .empty { color: #888; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th { background: #444; padding: 10px; text-align: left; }
        td { padding: 8px; border-bottom: 1px solid #444; }
        tr:hover { background: #333; }
        .completion { font-size: 48px; color: #ff4444; text-align: center; margin: 20px; }
    </style>
</head>
<body>
    <h1>🔥 BRUTAL AUDIT REPORT</h1>
    <p>Drive: $RootPath | Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
    
    <div class="completion">TRUE COMPLETION: $trueCompletion%</div>
    
    <h2>📊 Summary</h2>
    <div class="metric">
        <div class="metric-value">$($Stats.TotalFiles)</div>
        <div class="metric-label">Total Files</div>
    </div>
    <div class="metric">
        <div class="metric-value real">$($Stats.RealFiles)</div>
        <div class="metric-label">REAL ($realPercent%)</div>
    </div>
    <div class="metric">
        <div class="metric-value partial">$($Results | Where-Object { $_.Status -eq "PARTIAL" } | Measure-Object | Select-Object -ExpandProperty Count)</div>
        <div class="metric-label">PARTIAL</div>
    </div>
    <div class="metric">
        <div class="metric-value scaffold">$($Stats.ScaffoldFiles)</div>
        <div class="metric-label">SCAFFOLD ($scaffoldPercent%)</div>
    </div>
    <div class="metric">
        <div class="metric-value stub">$($Stats.StubFiles)</div>
        <div class="metric-label">STUB ($stubPercent%)</div>
    </div>
    <div class="metric">
        <div class="metric-value empty">$($Stats.EmptyFiles)</div>
        <div class="metric-label">EMPTY ($emptyPercent%)</div>
    </div>
    
    <h2>📂 Category Breakdown</h2>
    <table>
        <tr>
            <th>Category</th>
            <th>Total</th>
            <th>REAL</th>
            <th>PARTIAL</th>
            <th>SCAFFOLD</th>
            <th>STUB</th>
            <th>Completion</th>
        </tr>
"@

foreach ($group in $categoryGroups) {
    $realInCat = ($group.Group | Where-Object { $_.Status -eq "REAL" }).Count
    $stubInCat = ($group.Group | Where-Object { $_.Status -eq "STUB" }).Count
    $scaffoldInCat = ($group.Group | Where-Object { $_.Status -eq "SCAFFOLD" }).Count
    $partialInCat = ($group.Group | Where-Object { $_.Status -eq "PARTIAL" }).Count
    $totalInCat = $group.Group.Count
    
    $catCompletion = if ($totalInCat -gt 0) {
        [math]::Round((($realInCat + ($partialInCat * 0.5) + ($scaffoldInCat * 0.1)) / $totalInCat) * 100, 1)
    } else { 0 }
    
    $html += @"
        <tr>
            <td>$($group.Name)</td>
            <td>$totalInCat</td>
            <td class="real">$realInCat</td>
            <td class="partial">$partialInCat</td>
            <td class="scaffold">$scaffoldInCat</td>
            <td class="stub">$stubInCat</td>
            <td><strong>$catCompletion%</strong></td>
        </tr>
"@
}

$html += @"
    </table>
    
    <h2>❌ Top 50 STUB Files</h2>
    <table>
        <tr>
            <th>File</th>
            <th>Lines</th>
            <th>Category</th>
            <th>Path</th>
        </tr>
"@

$topStubs = $Results | Where-Object { $_.Status -eq "STUB" } | Sort-Object Lines -Descending | Select-Object -First 50
foreach ($file in $topStubs) {
    $html += @"
        <tr>
            <td class="stub">$($file.File)</td>
            <td>$($file.Lines)</td>
            <td>$($file.Category)</td>
            <td>$($file.Path)</td>
        </tr>
"@
}

$html += @"
    </table>
    
    <h2>⚠️ Top 50 SCAFFOLD Files</h2>
    <table>
        <tr>
            <th>File</th>
            <th>Lines</th>
            <th>Category</th>
            <th>Path</th>
        </tr>
"@

$topScaffolds = $Results | Where-Object { $_.Status -eq "SCAFFOLD" } | Sort-Object Lines -Descending | Select-Object -First 50
foreach ($file in $topScaffolds) {
    $html += @"
        <tr>
            <td class="scaffold">$($file.File)</td>
            <td>$($file.Lines)</td>
            <td>$($file.Category)</td>
            <td>$($file.Path)</td>
        </tr>
"@
}

$html += @"
    </table>
    
    <p style="margin-top: 40px; text-align: center; color: #888;">
        Generated by BRUTAL_FULL_DRIVE_AUDIT.ps1<br>
        NO SHINE BOX - JUST BRUTAL TRUTH
    </p>
</body>
</html>
"@

# Save HTML report
$html | Out-File -FilePath $OutputFile -Encoding UTF8
Write-Host ""
Write-Host "📄 HTML Report saved: $OutputFile" -ForegroundColor Green

# Open report
if (Test-Path $OutputFile) {
    try {
        Start-Process $OutputFile
        Write-Host "🌐 Report opened in browser" -ForegroundColor Green
    } catch {
        Write-Host "📂 Report saved. Open manually: $OutputFile" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Red
Write-Host "✅ BRUTAL AUDIT COMPLETE" -ForegroundColor Red
Write-Host "========================================" -ForegroundColor Red
Write-Host ""

# Return results
return [PSCustomObject]@{
    TotalFiles = $Stats.TotalFiles
    RealFiles = $Stats.RealFiles
    StubFiles = $Stats.StubFiles
    ScaffoldFiles = $Stats.ScaffoldFiles
    EmptyFiles = $Stats.EmptyFiles
    TrueCompletion = $trueCompletion
    Results = $Results
}
