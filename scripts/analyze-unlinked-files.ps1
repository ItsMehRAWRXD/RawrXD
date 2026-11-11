# RawrXD Unlinked Source File Analyzer
# Analyzes the ~9,001 unlinked source files to categorize and prioritize them

param(
    [string]$CMakeListsPath = "CMakeLists.txt",
    [string]$SourceRoot = ".",
    [string]$OutputPath = "analysis/unlinked-files",
    [switch]$GenerateReport,
    [switch]$SuggestIntegration,
    [int]$MinLinesOfCode = 50
)

$ErrorActionPreference = "Stop"

# File categories for classification
$FileCategories = @{
    CoreKernel = @("sovereign", "kernel", "core", "engine", "runtime")
    GGML = @("ggml", "gguf", "tensor", "compute", "matmul", "gemm")
    Attention = @("attention", "flashattention", "mha", "rope", "kv-cache")
    Normalization = @("rmsnorm", "layernorm", "norm", "softmax")
    Tokenizer = @("token", "bpe", "sentencepiece", "vocab")
    Memory = @("memory", "alloc", "pool", "buffer", "mmap")
    IO = @("io", "file", "load", "save", "serialize")
    GPU = @("cuda", "vulkan", "gpu", "device", "backend")
    ASM = @("asm", "assembly", "simd", "avx", "sse", "neon")
    Test = @("test", "bench", "validate", "verify", "mock")
    Stub = @("stub", "placeholder", "todo", "fixme")
    Experimental = @("exp", "experimental", "proto", "draft")
    Deprecated = @("deprecated", "old", "legacy", "backup")
}

$script:Results = @{
    Timestamp = Get-Date -Format "o"
    TotalUnlinked = 0
    Categories = @{}
    PriorityFiles = @()
    SuggestedIntegrations = @()
}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }
function Write-Error { param([string]$Message) Write-Host "[✗] $Message" -ForegroundColor Red }

function Initialize-Analyzer {
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    Write-Status "Analyzing unlinked source files..."
    Write-Status "CMakeLists: $CMakeListsPath"
    Write-Status "Source Root: $SourceRoot"
}

function Get-CMakeLinkedFiles {
    Write-Status "Extracting files linked in CMake..."
    
    $linkedFiles = @()
    
    if (Test-Path $CMakeListsPath) {
        $cmakeContent = Get-Content $CMakeListsPath -Raw
        
        # Find all source file references
        $patterns = @(
            'set\s*\(\s*\w+_SOURCES\s+([^)]+)\)',
            'target_sources\s*\([^)]+\s+([^)]+)\)',
            'add_executable\s*\(\s*\w+\s+([^)]+)\)',
            'add_library\s*\(\s*\w+\s+([^)]+)\)',
            '\$\{CMAKE_CURRENT_SOURCE_DIR\}/([^\s\)]+)',
            'file\s*\(\s*GLOB\s+\w+\s+"([^"]+)"'
        )
        
        foreach ($pattern in $patterns) {
            $matches = [regex]::Matches($cmakeContent, $pattern)
            foreach ($match in $matches) {
                $files = $match.Groups[1].Value -split '\s+' | Where-Object { $_ -match '\.(cpp|c|h|hpp|asm|S)$' }
                $linkedFiles += $files
            }
        }
    }
    
    # Recursively check all CMakeLists.txt files
    $allCMakeFiles = Get-ChildItem -Path $SourceRoot -Filter "CMakeLists.txt" -Recurse
    foreach ($cmakeFile in $allCMakeFiles) {
        $content = Get-Content $cmakeFile.FullName -Raw
        foreach ($pattern in $patterns) {
            $matches = [regex]::Matches($content, $pattern)
            foreach ($match in $matches) {
                $files = $match.Groups[1].Value -split '\s+' | Where-Object { $_ -match '\.(cpp|c|h|hpp|asm|S)$' }
                $linkedFiles += $files
            }
        }
    }
    
    return $linkedFiles | Select-Object -Unique
}

function Get-AllSourceFiles {
    Write-Status "Discovering all source files..."
    
    $extensions = @("*.cpp", "*.c", "*.h", "*.hpp", "*.asm", "*.S")
    $allFiles = @()
    
    foreach ($ext in $extensions) {
        $files = Get-ChildItem -Path $SourceRoot -Filter $ext -Recurse -ErrorAction SilentlyContinue
        $allFiles += $files
    }
    
    return $allFiles
}

function Find-UnlinkedFiles {
    param([array]$AllFiles, [array]$LinkedFiles)
    
    Write-Status "Identifying unlinked files..."
    
    $unlinked = @()
    
    foreach ($file in $AllFiles) {
        $relativePath = $file.FullName.Replace((Resolve-Path $SourceRoot).Path, "").TrimStart("\", "/")
        $fileName = $file.Name
        
        $isLinked = $false
        foreach ($linked in $LinkedFiles) {
            if ($relativePath -like "*$linked" -or $fileName -eq $linked) {
                $isLinked = $true
                break
            }
        }
        
        if (-not $isLinked) {
            $unlinked += $file
        }
    }
    
    return $unlinked
}

function Categorize-File {
    param([System.IO.FileInfo]$File)
    
    $name = $File.Name.ToLower()
    $path = $File.DirectoryName.ToLower()
    $content = ""
    
    # Try to read first 1KB for content analysis
    try {
        $content = Get-Content $File.FullName -TotalCount 50 -Raw -ErrorAction SilentlyContinue
    } catch {}
    
    $categories = @()
    
    # Check file name and path against categories
    foreach ($category in $FileCategories.Keys) {
        $keywords = $FileCategories[$category]
        foreach ($keyword in $keywords) {
            if ($name -like "*$keyword*" -or $path -like "*$keyword*") {
                $categories += $category
                break
            }
        }
    }
    
    # Content-based categorization
    if ($content -match "__asm__|asm\s+|\.byte\s+|nop\s*\n") {
        $categories += "ASM"
    }
    if ($content -match "test\s*\(|TEST\s*\(|benchmark|BENCHMARK") {
        $categories += "Test"
    }
    if ($content -match "TODO|FIXME|XXX|HACK|STUB" -and $categories -notcontains "Stub") {
        $categories += "Stub"
    }
    if ($content -match "experimental|prototype|draft" -and $categories -notcontains "Experimental") {
        $categories += "Experimental"
    }
    
    # If no category matched, mark as Uncategorized
    if ($categories.Count -eq 0) {
        $categories += "Uncategorized"
    }
    
    return $categories | Select-Object -Unique
}

function Get-FilePriority {
    param([System.IO.FileInfo]$File, [array]$Categories)
    
    $score = 0
    $reasons = @()
    
    # Size-based scoring
    $lines = 0
    try {
        $lines = (Get-Content $File.FullName -ErrorAction SilentlyContinue).Count
    } catch {}
    
    if ($lines -gt 1000) {
        $score += 10
        $reasons += "Large file ($lines lines)"
    } elseif ($lines -gt 500) {
        $score += 5
        $reasons += "Medium file ($lines lines)"
    } elseif ($lines -lt $MinLinesOfCode) {
        $score -= 5
        $reasons += "Small file ($lines lines)"
    }
    
    # Category-based scoring
    $highValueCategories = @("CoreKernel", "GGML", "Attention", "GPU", "ASM")
    $mediumValueCategories = @("Normalization", "Tokenizer", "Memory", "IO")
    $lowValueCategories = @("Stub", "Experimental", "Deprecated", "Test")
    
    foreach ($cat in $Categories) {
        if ($highValueCategories -contains $cat) {
            $score += 15
            $reasons += "High-value category: $cat"
        } elseif ($mediumValueCategories -contains $cat) {
            $score += 8
            $reasons += "Medium-value category: $cat"
        } elseif ($lowValueCategories -contains $cat) {
            $score -= 3
            $reasons += "Low-value category: $cat"
        }
    }
    
    # Path-based scoring
    $path = $File.FullName.ToLower()
    if ($path -like "*src/core*" -or $path -like "*src/kernel*") {
        $score += 10
        $reasons += "Core source location"
    }
    if ($path -like "*test*" -or $path -like "*bench*") {
        $score -= 5
        $reasons += "Test/Benchmark location"
    }
    if ($path -like "*deprecated*" -or $path -like "*old*") {
        $score -= 10
        $reasons += "Deprecated location"
    }
    
    # File extension scoring
    if ($File.Extension -eq ".asm" -or $File.Extension -eq ".S") {
        $score += 5
        $reasons += "Assembly code (performance-critical)"
    }
    
    return @{
        Score = $score
        Reasons = $reasons
        Lines = $lines
    }
}

function Analyze-UnlinkedFiles {
    param([array]$UnlinkedFiles)
    
    Write-Status "Categorizing $($UnlinkedFiles.Count) unlinked files..."
    
    $script:Results.TotalUnlinked = $UnlinkedFiles.Count
    
    foreach ($file in $UnlinkedFiles) {
        $categories = Categorize-File -File $file
        $priority = Get-FilePriority -File $file -Categories $categories
        
        # Add to category counts
        foreach ($cat in $categories) {
            if (-not $script:Results.Categories.ContainsKey($cat)) {
                $script:Results.Categories[$cat] = @{
                    Count = 0
                    Files = @()
                }
            }
            $script:Results.Categories[$cat].Count++
            $script:Results.Categories[$cat].Files += $file.Name
        }
        
        # Track high-priority files
        if ($priority.Score -gt 15) {
            $script:Results.PriorityFiles += @{
                File = $file.FullName
                Score = $priority.Score
                Reasons = $priority.Reasons
                Categories = $categories
                Lines = $priority.Lines
            }
        }
    }
    
    # Sort priority files by score
    $script:Results.PriorityFiles = $script:Results.PriorityFiles | Sort-Object -Property Score -Descending
}

function Generate-IntegrationSuggestions {
    Write-Status "Generating CMake integration suggestions..."
    
    $topFiles = $script:Results.PriorityFiles | Select-Object -First 50
    
    foreach ($fileInfo in $topFiles) {
        $file = Get-Item $fileInfo.File
        $relativePath = $file.FullName.Replace((Resolve-Path $SourceRoot).Path, "").TrimStart("\", "/")
        
        $suggestion = @{
            File = $relativePath
            Score = $fileInfo.Score
            Reason = ($fileInfo.Reasons | Select-Object -First 3) -join "; "
            SuggestedTarget = ""
        }
        
        # Suggest target based on category
        $categories = $fileInfo.Categories
        if ($categories -contains "CoreKernel") {
            $suggestion.SuggestedTarget = "rawrxd_core"
        } elseif ($categories -contains "GGML") {
            $suggestion.SuggestedTarget = "ggml"
        } elseif ($categories -contains "GPU") {
            $suggestion.SuggestedTarget = "gpu_backend"
        } elseif ($categories -contains "ASM") {
            $suggestion.SuggestedTarget = "asm_kernels"
        } elseif ($categories -contains "Test") {
            $suggestion.SuggestedTarget = "test_suite"
        } else {
            $suggestion.SuggestedTarget = "rawrxd_sources"
        }
        
        $script:Results.SuggestedIntegrations += $suggestion
    }
}

function Export-AnalysisReport {
    Write-Status "Exporting analysis report..."
    
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $reportFile = "$OutputPath\unlinked-analysis-$timestamp.json"
    
    $script:Results | ConvertTo-Json -Depth 10 | Out-File $reportFile
    Write-Success "JSON report: $reportFile"
    
    # Generate HTML report
    $htmlFile = "$OutputPath\unlinked-analysis-$timestamp.html"
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD Unlinked Files Analysis</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { background: white; padding: 20px; border-radius: 8px; }
        h1 { color: #333; }
        .metric { display: inline-block; margin: 10px 20px 10px 0; padding: 15px; background: #f0f0f0; border-radius: 4px; }
        .high { color: #d32f2f; font-weight: bold; }
        .medium { color: #f57c00; }
        .low { color: #689f38; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { text-align: left; padding: 12px; border-bottom: 1px solid #ddd; }
        th { background: #4CAF50; color: white; }
        tr:hover { background: #f5f5f5; }
        .category { display: inline-block; padding: 4px 8px; border-radius: 4px; margin: 2px; }
        .category-CoreKernel { background: #d32f2f; color: white; }
        .category-GGML { background: #f57c00; color: white; }
        .category-Attention { background: #1976d2; color: white; }
        .category-GPU { background: #7b1fa2; color: white; }
        .category-ASM { background: #5d4037; color: white; }
        .category-Test { background: #616161; color: white; }
        .category-Stub { background: #9e9e9e; color: white; }
    </style>
</head>
<body>
    <div class="container">
        <h1>RawrXD Unlinked Source Files Analysis</h1>
        <p>Generated: $($script:Results.Timestamp)</p>
        
        <div class="metric">
            <strong>Total Unlinked Files:</strong> 
            <span class="high">$($script:Results.TotalUnlinked)</span>
        </div>
        
        <h2>Categories</h2>
        <table>
            <tr><th>Category</th><th>Count</th><th>Percentage</th></tr>
"@
    
    foreach ($cat in $script:Results.Categories.Keys | Sort-Object { $script:Results.Categories[$_].Count } -Descending) {
        $count = $script:Results.Categories[$cat].Count
        $percent = [math]::Round(($count / $script:Results.TotalUnlinked) * 100, 1)
        $html += "<tr><td><span class='category category-$cat'>$cat</span></td><td>$count</td><td>$percent%</td></tr>"
    }
    
    $html += @"
        </table>
        
        <h2>High Priority Files (Top 30)</h2>
        <table>
            <tr><th>File</th><th>Score</th><th>Categories</th><th>Lines</th><th>Reason</th></tr>
"@
    
    foreach ($file in $script:Results.PriorityFiles | Select-Object -First 30) {
        $catBadges = ($file.Categories | ForEach-Object { "<span class='category category-$_'>$_</span>" }) -join " "
        $html += "<tr><td>$($file.File)</td><td class='high'>$($file.Score)</td><td>$catBadges</td><td>$($file.Lines)</td><td>$($file.Reasons[0])</td></tr>"
    }
    
    $html += @"
        </table>
        
        <h2>Suggested CMake Integrations (Top 20)</h2>
        <table>
            <tr><th>File</th><th>Target</th><th>Score</th></tr>
"@
    
    foreach ($suggestion in $script:Results.SuggestedIntegrations | Select-Object -First 20) {
        $html += "<tr><td>$($suggestion.File)</td><td><code>$($suggestion.SuggestedTarget)</code></td><td>$($suggestion.Score)</td></tr>"
    }
    
    $html += @"
        </table>
    </div>
</body>
</html>
"@
    
    $html | Out-File $htmlFile
    Write-Success "HTML report: $htmlFile"
    
    # Generate CMake suggestions file
    if ($SuggestIntegration) {
        $cmakeFile = "$OutputPath\suggested-cmake-additions.cmake"
        $cmakeContent = "# Suggested CMake additions based on unlinked file analysis`n"
        $cmakeContent += "# Generated: $(Get-Date -Format 'o')`n`n"
        
        $grouped = $script:Results.SuggestedIntegrations | Group-Object -Property SuggestedTarget
        
        foreach ($group in $grouped) {
            $cmakeContent += "# $($group.Name) additions`n"
            $cmakeContent += "target_sources(`$($group.Name) PRIVATE`n"
            foreach ($item in $group.Group | Select-Object -First 10) {
                $cmakeContent += "    `$CMAKE_CURRENT_SOURCE_DIR/$($item.File)`n"
            }
            $cmakeContent += ")`n`n"
        }
        
        $cmakeContent | Out-File $cmakeFile
        Write-Success "CMake suggestions: $cmakeFile"
    }
}

function Show-Summary {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Unlinked Files Analysis Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Total Unlinked Files: $($script:Results.TotalUnlinked)" -ForegroundColor White
    Write-Host ""
    
    Write-Host "Breakdown by Category:" -ForegroundColor White
    foreach ($cat in $script:Results.Categories.Keys | Sort-Object { $script:Results.Categories[$_].Count } -Descending) {
        $count = $script:Results.Categories[$cat].Count
        $percent = [math]::Round(($count / $script:Results.TotalUnlinked) * 100, 1)
        Write-Host "  $cat`: $count ($percent%)" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "High Priority Files: $($script:Results.PriorityFiles.Count)" -ForegroundColor Yellow
    Write-Host "Suggested Integrations: $($script:Results.SuggestedIntegrations.Count)" -ForegroundColor Green
    
    Write-Host ""
    Write-Warning "~91% of source files are not linked in CMake"
    Write-Host "Review the generated reports for integration recommendations." -ForegroundColor Gray
}

# Main execution
function Main {
    Write-Host "RawrXD Unlinked Source File Analyzer" -ForegroundColor Cyan
    Write-Host "===================================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-Analyzer
    
    $linkedFiles = Get-CMakeLinkedFiles
    $allFiles = Get-AllSourceFiles
    $unlinkedFiles = Find-UnlinkedFiles -AllFiles $allFiles -LinkedFiles $linkedFiles
    
    Analyze-UnlinkedFiles -UnlinkedFiles $unlinkedFiles
    
    if ($SuggestIntegration) {
        Generate-IntegrationSuggestions
    }
    
    if ($GenerateReport) {
        Export-AnalysisReport
    }
    
    Show-Summary
    
    Write-Host ""
    Write-Success "Analysis complete!"
}

Main
