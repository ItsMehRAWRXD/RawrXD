# d:\rawrxd\audit_all_features.ps1
# Complete Feature Audit - Scans entire drive for REAL vs STUB code
# Part of RawrXD Production Suite

param(
    [string]$RootPath = "D:\",
    [string]$OutputFile = "feature_audit_report.html",
    [switch]$Detailed,
    [switch]$IncludeBackups,
    [int]$MaxFileSizeKB = 1024
)

$ErrorActionPreference = "Continue"
$ProgressPreference = "Continue"

# Colors for console output
$Colors = @{
    "REAL" = "Green"
    "STUB" = "Red"
    "PARTIAL" = "Yellow"
    "UNKNOWN" = "Gray"
    "HEADER" = "Cyan"
    "INFO" = "White"
}

# Feature categories with search patterns
$Categories = @{
    "Ghost Text" = @("ghost_text", "GhostText", "ghost-text", "inline_completion", "InlineCompletion", "text_edit", "TextEdit")
    "Model Loading" = @("gguf_loader", "GGUF", "safetensors", "SafeTensors", "pytorch", "PyTorch", "onnx", "ONNX", "model_loader", "streaming_loader")
    "Native Compiler" = @("universal_compiler", "language_backend", "minimal_assembler", "linker", "c_compiler", "c_lexer", "c_parser", "c_ir")
    "Binary Patching" = @("binary_patch", "patch_pipeline", "pe_patcher", "pe_analyzer", "pe_fixer", "hotpatch", "HotPatch")
    "Agentic Framework" = @("agentic_executor", "tool_registry", "autonomous_agent", "slash_command", "plan_orchestrator", "swarm_coordinator")
    "Memory System" = @("agentic_memory", "vector_search", "memory_store", "memory_hotpatcher", "MemoryGuard")
    "Win32IDE" = @("win32ide", "chat_panel", "sidebar", "lsp_bridge", "debugger", "dap_server", "inline_edit")
    "Security" = @("jwt", "rbac", "audit", "sandbox", "quantum_auth", "keystore", "policy_engine")
    "Reverse Engineering" = @("codex_bridge", "codex_native", "pe_analyzer", "disassembler", "reverser", "deobfuscator")
    "AI Inference" = @("cuda_backend", "amd_backend", "cpu_backend", "inference_engine", "vulkan_backend", "gpu_backend")
    "LSP/DAP" = @("lsp_server", "dap_adapter", "language_server", "debug_adapter", "jsonrpc")
    "Telemetry" = @("telemetry", "metrics", "benchmark", "profiler", "sovereign")
    "Build System" = @("build_pipeline", "cmake", "ninja", "msbuild", "task_system")
}

# Patterns that indicate STUB/SCAFFOLDING
$StubPatterns = @(
    "//\s*TODO",
    "//\s*FIXME",
    "//\s*STUB",
    "//\s*stub",
    "//\s*Scaffolding",
    "throw\s+new\s+NotImplementedException",
    "return\s+0\s*;\s*//\s*stub",
    "printf.*STUB",
    "//\s*Not\s+implemented",
    "//\s*Placeholder",
    "return\s+nullptr\s*;\s*//\s*stub",
    "//\s*This\s+is\s+a\s*stub",
    "TODO:\s*Implement",
    "FIXME:\s*Implement",
    "//\s*@stub",
    "//\s*@wip",
    "throw\s+std::runtime_error.*Not\s+implemented",
    "//\s*Temporary",
    "//\s*HACK",
    "//\s*XXX",
    "//\s*NOTE:\s*Not\s+implemented",
    "return\s+false\s*;\s*//\s*TODO",
    "return\s+true\s*;\s*//\s*TODO",
    "//\s*Coming\s+soon",
    "//\s*Under\s+construction",
    "//\s*Incomplete",
    "//\s*Draft",
    "//\s*Prototype"
)

# REAL implementation patterns
$RealPatterns = @(
    "class.*public:.*private:",
    "int\s+main",
    "WINAPI",
    "DWORD\s+WINAPI",
    "__declspec",
    "typedef\s+struct",
    "template",
    "CreateFile",
    "ReadFile",
    "WriteFile",
    "VirtualAlloc",
    "VirtualFree",
    "malloc",
    "free",
    "new\s+\w+",
    "delete\s+",
    "std::",
    "printf",
    "fprintf",
    "sprintf",
    "fopen",
    "fclose",
    "fread",
    "fwrite",
    "socket",
    "connect",
    "bind",
    "listen",
    "accept",
    "send",
    "recv"
)

# File extensions to scan
$FileExtensions = @(".cpp", ".c", ".h", ".hpp", ".cs", ".js", ".ts", ".py", ".go", ".rs", ".asm", ".bat", ".ps1", ".java", ".kt", ".swift", ".m", ".mm")

# Excluded directories
$ExcludedDirs = @("node_modules", ".git", "build", "bin", "obj", ".vs", ".vscode", "__pycache__", "vendor", "third_party", "3rdparty", "archive", ".archive", "backups", ".backups")
if (-not $IncludeBackups) {
    $ExcludedDirs += @("*.backup", "*.bak", "*.old", "*.orig")
}

# Statistics
$Stats = @{
    TotalFiles = 0
    RealFiles = 0
    StubFiles = 0
    PartialFiles = 0
    TotalLines = 0
    TotalSizeKB = 0
    StartTime = Get-Date
}

# Scan function
function Scan-Features {
    param(
        [string]$Path,
        [string]$Category,
        [string[]]$Patterns,
        [string]$Type
    )
    
    $results = @()
    
    foreach ($pattern in $Patterns) {
        try {
            $files = Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue | 
                     Where-Object { 
                         $ext = $_.Extension.ToLower()
                         $FileExtensions -contains $ext -and
                         $_.Length -lt ($MaxFileSizeKB * 1024) -and
                         ($ExcludedDirs | ForEach-Object { $_.FullName -notlike "*$_*" } | Where-Object { $_ -eq $true } | Measure-Object).Count -eq 0
                     } |
                     Select-String -Pattern $pattern -SimpleMatch -ErrorAction SilentlyContinue |
                     Select-Object -Unique Filename, Path, LineNumber
            
            foreach ($file in $files) {
                try {
                    $fileInfo = Get-Item $file.Path -ErrorAction SilentlyContinue
                    if (-not $fileInfo) { continue }
                    
                    $lines = (Get-Content $file.Path -ErrorAction SilentlyContinue | Measure-Object -Line).Lines
                    $size = $fileInfo.Length / 1024
                    
                    # Check if it's REAL or STUB
                    $content = Get-Content $file.Path -Raw -ErrorAction SilentlyContinue
                    if (-not $content) { continue }
                    
                    $isStub = $false
                    $stubMatch = ""
                    foreach ($stubPattern in $StubPatterns) {
                        if ($content -match $stubPattern) {
                            $isStub = $true
                            $stubMatch = $stubPattern
                            break
                        }
                    }
                    
                    # Check for real code indicators
                    $hasRealCode = $false
                    $realCodeCount = 0
                    foreach ($realPattern in $RealPatterns) {
                        $matches = [regex]::Matches($content, $realPattern)
                        $realCodeCount += $matches.Count
                        if ($matches.Count -gt 0) {
                            $hasRealCode = $true
                        }
                    }
                    
                    # Determine status
                    $status = if ($isStub -and -not $hasRealCode) { 
                        "STUB" 
                    } elseif ($isStub -and $hasRealCode) { 
                        "PARTIAL" 
                    } elseif ($hasRealCode) { 
                        "REAL" 
                    } else { 
                        "UNKNOWN" 
                    }
                    
                    $results += [PSCustomObject]@{
                        Category = $Category
                        File = $file.Filename
                        Path = $file.Path
                        Lines = $lines
                        SizeKB = [math]::Round($size, 2)
                        Status = $status
                        Type = $Type
                        RealCodeIndicators = $realCodeCount
                        StubPattern = if ($stubMatch) { $stubMatch } else { "None" }
                    }
                    
                    # Update stats
                    $Stats.TotalFiles++
                    $Stats.TotalLines += $lines
                    $Stats.TotalSizeKB += $size
                    
                    switch ($status) {
                        "REAL" { $Stats.RealFiles++ }
                        "STUB" { $Stats.StubFiles++ }
                        "PARTIAL" { $Stats.PartialFiles++ }
                    }
                }
                catch {
                    Write-Verbose "Error processing file: $($file.Path) - $_"
                }
            }
        }
        catch {
            Write-Verbose "Error scanning pattern '$pattern': $_"
        }
    }
    
    return $results
}

# Progress function
function Show-Progress {
    param(
        [string]$Activity,
        [int]$PercentComplete
    )
    Write-Progress -Activity $Activity -PercentComplete $PercentComplete -Status "$PercentComplete% Complete"
}

# Main audit
Write-Host ""
Write-Host "========================================" -ForegroundColor $Colors.HEADER
Write-Host "🔍 RAWRXD FEATURE AUDIT" -ForegroundColor $Colors.HEADER
Write-Host "========================================" -ForegroundColor $Colors.HEADER
Write-Host ""
Write-Host "Root Path: $RootPath" -ForegroundColor $Colors.INFO
Write-Host "Output File: $OutputFile" -ForegroundColor $Colors.INFO
Write-Host "Max File Size: $MaxFileSizeKB KB" -ForegroundColor $Colors.INFO
Write-Host "Include Backups: $IncludeBackups" -ForegroundColor $Colors.INFO
Write-Host ""
Write-Host "Scanning..." -ForegroundColor Yellow
Write-Host ""

$allResults = @()
$categoryCount = $Categories.Count
$currentCategory = 0

foreach ($category in $Categories.Keys) {
    $currentCategory++
    $percentComplete = [math]::Round(($currentCategory / $categoryCount) * 100)
    Show-Progress -Activity "Scanning Categories" -PercentComplete $percentComplete
    
    Write-Host "[$currentCategory/$categoryCount] Scanning: $category" -ForegroundColor Yellow
    $patterns = $Categories[$category]
    $results = Scan-Features -Path $RootPath -Category $category -Patterns $patterns -Type "Feature"
    $allResults += $results
    
    $realCount = ($results | Where-Object { $_.Status -eq "REAL" }).Count
    $stubCount = ($results | Where-Object { $_.Status -eq "STUB" }).Count
    $partialCount = ($results | Where-Object { $_.Status -eq "PARTIAL" }).Count
    
    Write-Host "  Found $($results.Count) files (REAL: $realCount, PARTIAL: $partialCount, STUB: $stubCount)" -ForegroundColor Gray
}

Write-Progress -Activity "Scanning Categories" -Completed

# Calculate duration
$endTime = Get-Date
$duration = $endTime - $Stats.StartTime

# Count by status
$statusCounts = $allResults | Group-Object Status
$realCount = ($statusCounts | Where-Object { $_.Name -eq "REAL" } | Select-Object -ExpandProperty Count) -or 0
$stubCount = ($statusCounts | Where-Object { $_.Name -eq "STUB" } | Select-Object -ExpandProperty Count) -or 0
$partialCount = ($statusCounts | Where-Object { $_.Name -eq "PARTIAL" } | Select-Object -ExpandProperty Count) -or 0
$unknownCount = ($statusCounts | Where-Object { $_.Name -eq "UNKNOWN" } | Select-Object -ExpandProperty Count) -or 0

# Console summary
Write-Host ""
Write-Host "========================================" -ForegroundColor $Colors.HEADER
Write-Host "📊 AUDIT SUMMARY" -ForegroundColor $Colors.HEADER
Write-Host "========================================" -ForegroundColor $Colors.HEADER
Write-Host ""
Write-Host "Duration: $($duration.ToString('hh\:mm\:ss'))" -ForegroundColor $Colors.INFO
Write-Host ""
Write-Host "Total Files Scanned: $($allResults.Count)" -ForegroundColor White
Write-Host "  ✅ REAL: $realCount" -ForegroundColor $Colors.REAL
Write-Host "  ⚠️  PARTIAL: $partialCount" -ForegroundColor $Colors.PARTIAL
Write-Host "  ❌ STUB: $stubCount" -ForegroundColor $Colors.STUB
if ($unknownCount -gt 0) {
    Write-Host "  ❓ UNKNOWN: $unknownCount" -ForegroundColor $Colors.UNKNOWN
}
Write-Host ""
Write-Host "Total Lines of Code: $([math]::Round($Stats.TotalLines, 0).ToString('N0'))" -ForegroundColor White
Write-Host "Total Size: $([math]::Round($Stats.TotalSizeKB / 1024, 2)) MB" -ForegroundColor White
Write-Host ""

# Category breakdown
Write-Host "📂 CATEGORY BREAKDOWN" -ForegroundColor $Colors.HEADER
Write-Host "========================================" -ForegroundColor $Colors.HEADER
Write-Host ""

$categoryGroups = $allResults | Group-Object Category | Sort-Object Name
foreach ($group in $categoryGroups) {
    $realInCat = ($group.Group | Where-Object { $_.Status -eq "REAL" }).Count
    $stubInCat = ($group.Group | Where-Object { $_.Status -eq "STUB" }).Count
    $partialInCat = ($group.Group | Where-Object { $_.Status -eq "PARTIAL" }).Count
    $totalInCat = $group.Group.Count
    
    $color = if ($realInCat -gt $stubInCat) { $Colors.REAL } elseif ($stubInCat -gt $realInCat) { $Colors.STUB } else { $Colors.PARTIAL }
    
    Write-Host "  $($group.Name):" -ForegroundColor Yellow
    Write-Host "    Total: $totalInCat | REAL: $realInCat | PARTIAL: $partialInCat | STUB: $stubInCat" -ForegroundColor $color
}

Write-Host ""

# Detailed output if requested
if ($Detailed) {
    Write-Host "📋 DETAILED FILE LIST" -ForegroundColor $Colors.HEADER
    Write-Host "========================================" -ForegroundColor $Colors.HEADER
    Write-Host ""
    
    foreach ($result in $allResults | Sort-Object Category, Status, File | Select-Object -First 50) {
        $color = switch ($result.Status) {
            "REAL" { $Colors.REAL }
            "STUB" { $Colors.STUB }
            "PARTIAL" { $Colors.PARTIAL }
            default { $Colors.UNKNOWN }
        }
        
        Write-Host "  [$($result.Status)] $($result.File)" -ForegroundColor $color
        Write-Host "      Category: $($result.Category) | Lines: $($result.Lines) | Size: $($result.SizeKB) KB" -ForegroundColor Gray
        if ($result.StubPattern -ne "None") {
            Write-Host "      Stub Pattern: $($result.StubPattern)" -ForegroundColor Red
        }
        if ($Detailed) {
            Write-Host "      Path: $($result.Path)" -ForegroundColor DarkGray
        }
        Write-Host ""
    }
    
    if ($allResults.Count -gt 50) {
        Write-Host "  ... and $($allResults.Count - 50) more files (see HTML report)" -ForegroundColor Gray
    }
}

# Generate HTML report
$html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RawrXD Feature Audit Report</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 20px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header p { font-size: 1.2em; opacity: 0.9; }
        .content { padding: 40px; }
        .summary { 
            display: grid; 
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
            gap: 20px; 
            margin-bottom: 40px;
        }
        .metric-card {
            background: #f8f9fa;
            border-radius: 12px;
            padding: 24px;
            text-align: center;
            border-left: 4px solid;
            transition: transform 0.2s;
        }
        .metric-card:hover { transform: translateY(-5px); }
        .metric-card.total { border-left-color: #6c757d; }
        .metric-card.real { border-left-color: #28a745; }
        .metric-card.partial { border-left-color: #ffc107; }
        .metric-card.stub { border-left-color: #dc3545; }
        .metric-value { 
            font-size: 36px; 
            font-weight: bold; 
            display: block; 
            margin-bottom: 8px;
        }
        .metric-card.total .metric-value { color: #6c757d; }
        .metric-card.real .metric-value { color: #28a745; }
        .metric-card.partial .metric-value { color: #ffc107; }
        .metric-card.stub .metric-value { color: #dc3545; }
        .metric-label { font-size: 14px; color: #666; text-transform: uppercase; letter-spacing: 1px; }
        .section { margin-bottom: 40px; }
        .section h2 { 
            color: #333; 
            margin-bottom: 20px; 
            padding-bottom: 10px; 
            border-bottom: 2px solid #e0e0e0;
        }
        table { 
            width: 100%; 
            border-collapse: collapse; 
            background: white; 
            border-radius: 8px; 
            overflow: hidden; 
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        th { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            padding: 16px; 
            text-align: left; 
            font-weight: 600;
        }
        td { 
            padding: 14px 16px; 
            border-bottom: 1px solid #e0e0e0; 
        }
        tr:hover { background: #f8f9fa; }
        tr:last-child td { border-bottom: none; }
        .badge { 
            display: inline-block; 
            padding: 6px 14px; 
            border-radius: 20px; 
            color: white; 
            font-weight: bold; 
            font-size: 12px; 
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .badge-real { background: linear-gradient(135deg, #28a745, #20c997); }
        .badge-stub { background: linear-gradient(135deg, #dc3545, #e74c3c); }
        .badge-partial { background: linear-gradient(135deg, #ffc107, #ff9800); color: #333; }
        .badge-unknown { background: linear-gradient(135deg, #6c757d, #95a5a6); }
        .category-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
        }
        .category-card {
            background: #f8f9fa;
            border-radius: 12px;
            padding: 20px;
            border-left: 4px solid #667eea;
        }
        .category-card h3 {
            color: #333;
            margin-bottom: 12px;
            font-size: 1.1em;
        }
        .category-stats {
            display: flex;
            justify-content: space-between;
            margin-top: 10px;
        }
        .category-stat {
            text-align: center;
        }
        .category-stat-value {
            font-size: 24px;
            font-weight: bold;
            display: block;
        }
        .category-stat-label {
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
        }
        .footer {
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 14px;
        }
        .progress-bar {
            width: 100%;
            height: 8px;
            background: #e0e0e0;
            border-radius: 4px;
            overflow: hidden;
            margin-top: 10px;
        }
        .progress-fill {
            height: 100%;
            border-radius: 4px;
            transition: width 0.3s;
        }
        .progress-fill.real { background: #28a745; }
        .progress-fill.stub { background: #dc3545; }
        .progress-fill.partial { background: #ffc107; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 RawrXD Feature Audit Report</h1>
            <p>Complete analysis of REAL features vs STUB/SCAFFOLDING</p>
        </div>
        
        <div class="content">
            <div class="summary">
                <div class="metric-card total">
                    <span class="metric-value">$($allResults.Count)</span>
                    <span class="metric-label">Total Files</span>
                </div>
                <div class="metric-card real">
                    <span class="metric-value">$realCount</span>
                    <span class="metric-label">✅ REAL Features</span>
                </div>
                <div class="metric-card partial">
                    <span class="metric-value">$partialCount</span>
                    <span class="metric-label">⚠️ PARTIAL</span>
                </div>
                <div class="metric-card stub">
                    <span class="metric-value">$stubCount</span>
                    <span class="metric-label">❌ STUB/Scaffolding</span>
                </div>
            </div>
            
            <div class="section">
                <h2>📊 Code Statistics</h2>
                <div class="summary">
                    <div class="metric-card total">
                        <span class="metric-value">$([math]::Round($Stats.TotalLines, 0).ToString('N0'))</span>
                        <span class="metric-label">Total Lines</span>
                    </div>
                    <div class="metric-card total">
                        <span class="metric-value">$([math]::Round($Stats.TotalSizeKB / 1024, 2))</span>
                        <span class="metric-label">Total Size (MB)</span>
                    </div>
                    <div class="metric-card total">
                        <span class="metric-value">$($duration.ToString('hh\:mm\:ss'))</span>
                        <span class="metric-label">Scan Duration</span>
                    </div>
                    <div class="metric-card total">
                        <span class="metric-value">$([math]::Round(($realCount / ($allResults.Count + 1)) * 100, 1))%</span>
                        <span class="metric-label">Completion Rate</span>
                    </div>
                </div>
            </div>
            
            <div class="section">
                <h2>📂 Category Breakdown</h2>
                <div class="category-grid">
"@

foreach ($group in $categoryGroups) {
    $realInCat = ($group.Group | Where-Object { $_.Status -eq "REAL" }).Count
    $stubInCat = ($group.Group | Where-Object { $_.Status -eq "STUB" }).Count
    $partialInCat = ($group.Group | Where-Object { $_.Status -eq "PARTIAL" }).Count
    $totalInCat = $group.Group.Count
    
    $completionRate = if ($totalInCat -gt 0) { [math]::Round(($realInCat / $totalInCat) * 100, 1) } else { 0 }
    
    $html += @"
                    <div class="category-card">
                        <h3>$($group.Name)</h3>
                        <div class="category-stats">
                            <div class="category-stat">
                                <span class="category-stat-value" style="color: #333;">$totalInCat</span>
                                <span class="category-stat-label">Total</span>
                            </div>
                            <div class="category-stat">
                                <span class="category-stat-value" style="color: #28a745;">$realInCat</span>
                                <span class="category-stat-label">Real</span>
                            </div>
                            <div class="category-stat">
                                <span class="category-stat-value" style="color: #ffc107;">$partialInCat</span>
                                <span class="category-stat-label">Partial</span>
                            </div>
                            <div class="category-stat">
                                <span class="category-stat-value" style="color: #dc3545;">$stubInCat</span>
                                <span class="category-stat-label">Stub</span>
                            </div>
                        </div>
                        <div class="progress-bar">
                            <div class="progress-fill real" style="width: $completionRate%;"></div>
                        </div>
                        <p style="text-align: center; margin-top: 8px; font-size: 12px; color: #666;">$completionRate% Complete</p>
                    </div>
"@
}

$html += @"
                </div>
            </div>
            
            <div class="section">
                <h2>📋 Detailed File List</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Category</th>
                            <th>File</th>
                            <th>Status</th>
                            <th>Lines</th>
                            <th>Size (KB)</th>
                            <th>Real Code Indicators</th>
                        </tr>
                    </thead>
                    <tbody>
"@

foreach ($result in $allResults | Sort-Object Category, Status, File) {
    $badgeClass = switch ($result.Status) {
        "REAL" { "badge-real" }
        "STUB" { "badge-stub" }
        "PARTIAL" { "badge-partial" }
        default { "badge-unknown" }
    }
    
    $html += @"
                        <tr>
                            <td>$($result.Category)</td>
                            <td>$($result.File)</td>
                            <td><span class="badge $badgeClass">$($result.Status)</span></td>
                            <td>$($result.Lines)</td>
                            <td>$($result.SizeKB)</td>
                            <td>$($result.RealCodeIndicators)</td>
                        </tr>
"@
}

$html += @"
                    </tbody>
                </table>
            </div>
        </div>
        
        <div class="footer">
            <p>📄 Audit completed on $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")</p>
            <p>🔍 Root Path: $RootPath | Generated by RawrXD Feature Auditor</p>
        </div>
    </div>
</body>
</html>
"@

# Save HTML report
$html | Out-File -FilePath $OutputFile -Encoding UTF8

Write-Host ""
Write-Host "📄 HTML Report saved: $OutputFile" -ForegroundColor Green
Write-Host ""

# Try to open report
if (Test-Path $OutputFile) {
    try {
        Start-Process $OutputFile
        Write-Host "🌐 Report opened in browser" -ForegroundColor Green
    }
    catch {
        Write-Host "📂 Report saved. Open manually: $OutputFile" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor $Colors.HEADER
Write-Host "✅ AUDIT COMPLETE!" -ForegroundColor $Colors.HEADER
Write-Host "========================================" -ForegroundColor $Colors.HEADER
Write-Host ""

# Return results as objects
return $allResults
