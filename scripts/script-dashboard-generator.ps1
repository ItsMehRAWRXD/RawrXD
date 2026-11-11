# RawrXD Script Dashboard Generator
# Generates an interactive HTML dashboard for all scripts
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [string]$OutputPath = "script-dashboard.html",
    
    [Parameter()]
    [switch]$OpenAfter,
    
    [Parameter()]
    [switch]$IncludeMetrics
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }

function Get-ScriptInfo {
    param([string]$ScriptPath)
    
    $file = Get-Item $ScriptPath
    $content = Get-Content $ScriptPath -Raw -ErrorAction SilentlyContinue
    
    $category = "Other"
    $lowerName = $file.BaseName.ToLower()
    
    if ($lowerName -match "build|compile|make") { $category = "Build" }
    elseif ($lowerName -match "test|smoke|validate|verify|check") { $category = "Testing" }
    elseif ($lowerName -match "deploy|release|stage") { $category = "Deployment" }
    elseif ($lowerName -match "monitor|metric|log|health|diagnostic") { $category = "Monitoring" }
    elseif ($lowerName -match "config|setting|env|secret") { $category = "Configuration" }
    elseif ($lowerName -match "backup|restore|migrate") { $category = "Data Management" }
    elseif ($lowerName -match "benchmark|perf|profile") { $category = "Performance" }
    elseif ($lowerName -match "copilot|ai|agent") { $category = "AI/Copilot" }
    elseif ($lowerName -match "phase|soak|contract") { $category = "Validation" }
    elseif ($lowerName -match "debug|probe|capture|audit") { $category = "Diagnostics" }
    
    $lines = if ($content) { ($content -split "`n").Count } else { 0 }
    $functions = if ($content) { ([regex]::Matches($content, 'function\s+\w+')).Count } else { 0 }
    $parameters = if ($content) { ([regex]::Matches($content, '\[Parameter')).Count } else { 0 }
    
    return [PSCustomObject]@{
        Name = $file.BaseName
        Category = $category
        Size = $file.Length
        Lines = $lines
        Functions = $functions
        Parameters = $parameters
        Modified = $file.LastWriteTime
        Created = $file.CreationTime
    }
}

function Export-Dashboard {
    param([array]$Scripts, [string]$Path)
    
    $categories = $Scripts | Group-Object -Property Category | Sort-Object Name
    $totalScripts = $Scripts.Count
    $totalLines = ($Scripts | Measure-Object -Property Lines -Sum).Sum
    $totalFunctions = ($Scripts | Measure-Object -Property Functions -Sum).Sum
    
    $categoryData = $categories | ForEach-Object { 
        "{ name: '$($_.Name)', count: $($_.Count) }" 
    }
    
    $scriptsJson = $Scripts | Sort-Object Category, Name | ForEach-Object {
        $sizeKB = [math]::Round($_.Size / 1KB, 2)
        "{ name: '$($_.Name)', category: '$($_.Category)', lines: $($_.Lines), functions: $($_.Functions), params: $($_.Parameters), size: $sizeKB }"
    }
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RawrXD Script Dashboard</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            line-height: 1.6;
        }
        .header {
            background: linear-gradient(135deg, #1f6feb 0%, #238636 100%);
            padding: 40px;
            text-align: center;
        }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
        .header p { opacity: 0.9; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            max-width: 1400px;
            margin: 0 auto;
        }
        .stat-card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 25px;
            text-align: center;
            transition: transform 0.2s;
        }
        .stat-card:hover { transform: translateY(-5px); }
        .stat-value {
            font-size: 2.5em;
            font-weight: bold;
            background: linear-gradient(135deg, #58a6ff, #3fb950);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        .stat-label { color: #8b949e; margin-top: 5px; }
        .charts-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            padding: 30px;
            max-width: 1400px;
            margin: 0 auto;
        }
        .chart-card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 25px;
        }
        .chart-card h3 {
            color: #58a6ff;
            margin-bottom: 20px;
            text-align: center;
        }
        .scripts-table {
            max-width: 1400px;
            margin: 30px auto;
            padding: 0 30px;
        }
        .scripts-table h3 {
            color: #58a6ff;
            margin-bottom: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 12px;
            overflow: hidden;
        }
        th, td {
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #30363d;
        }
        th {
            background: #21262d;
            color: #58a6ff;
            font-weight: 600;
        }
        tr:hover { background: #1c2128; }
        .category-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 500;
        }
        .category-Build { background: #238636; }
        .category-Testing { background: #1f6feb; }
        .category-Deployment { background: #8957e5; }
        .category-Monitoring { background: #d29922; }
        .category-Configuration { background: #da3633; }
        .category-Performance { background: #2ea043; }
        .category-AI { background: #a371f7; }
        .category-Validation { background: #388bfd; }
        .category-Diagnostics { background: #f0883e; }
        .category-Other { background: #6e7681; }
        footer {
            text-align: center;
            padding: 30px;
            color: #6e7681;
            border-top: 1px solid #30363d;
            margin-top: 40px;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>🚀 RawrXD Script Dashboard</h1>
        <p>Complete DevOps Automation Suite Overview</p>
    </div>
    
    <div class="stats-grid">
        <div class="stat-card">
            <div class="stat-value">$totalScripts</div>
            <div class="stat-label">Total Scripts</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">$($categories.Count)</div>
            <div class="stat-label">Categories</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">$totalLines</div>
            <div class="stat-label">Total Lines</div>
        </div>
        <div class="stat-card">
            <div class="stat-value">$totalFunctions</div>
            <div class="stat-label">Functions</div>
        </div>
    </div>
    
    <div class="charts-container">
        <div class="chart-card">
            <h3>Scripts by Category</h3>
            <canvas id="categoryChart"></canvas>
        </div>
        <div class="chart-card">
            <h3>Code Distribution</h3>
            <canvas id="distributionChart"></canvas>
        </div>
    </div>
    
    <div class="scripts-table">
        <h3>All Scripts</h3>
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Category</th>
                    <th>Lines</th>
                    <th>Functions</th>
                    <th>Parameters</th>
                    <th>Size (KB)</th>
                </tr>
            </thead>
            <tbody>
"@

    foreach ($script in ($Scripts | Sort-Object Category, Name)) {
        $sizeKB = [math]::Round($script.Size / 1KB, 2)
        $html += @"
                <tr>
                    <td><strong>$($script.Name)</strong></td>
                    <td><span class="category-badge category-$($script.Category)">$($script.Category)</span></td>
                    <td>$($script.Lines)</td>
                    <td>$($script.Functions)</td>
                    <td>$($script.Parameters)</td>
                    <td>$sizeKB</td>
                </tr>
"@
    }

    $html += @"
            </tbody>
        </table>
    </div>
    
    <footer>
        <p>RawrXD Vision & Generation System v3.2.0</p>
        <p>Generated by script-dashboard-generator.ps1 v$script:Version</p>
    </footer>
    
    <script>
        const categoryData = [$($categoryData -join ', ')];
        const scriptsData = [$($scriptsJson -join ', ')];
        
        // Category Chart
        new Chart(document.getElementById('categoryChart'), {
            type: 'doughnut',
            data: {
                labels: categoryData.map(c => c.name),
                datasets: [{
                    data: categoryData.map(c => c.count),
                    backgroundColor: [
                        '#238636', '#1f6feb', '#8957e5', '#d29922',
                        '#da3633', '#2ea043', '#a371f7', '#388bfd', '#f0883e', '#6e7681'
                    ]
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'right', labels: { color: '#c9d1d9' } }
                }
            }
        });
        
        // Distribution Chart
        new Chart(document.getElementById('distributionChart'), {
            type: 'bar',
            data: {
                labels: ['Lines of Code', 'Functions', 'Parameters'],
                datasets: [{
                    label: 'Code Metrics',
                    data: [$totalLines, $totalFunctions, $($Scripts | Measure-Object -Property Parameters -Sum | Select-Object -ExpandProperty Sum)],
                    backgroundColor: ['#58a6ff', '#238636', '#d29922']
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    y: { ticks: { color: '#c9d1d9' }, grid: { color: '#30363d' } },
                    x: { ticks: { color: '#c9d1d9' }, grid: { color: '#30363d' } }
                }
            }
        });
    </script>
</body>
</html>
"@

    $html | Set-Content $Path -Encoding UTF8
    Write-Success "Dashboard generated: $Path"
}

# Main execution
try {
    Write-Status "Scanning scripts..."
    
    $scripts = Get-ChildItem -Path $PSScriptRoot -Filter "*.ps1" | ForEach-Object {
        Get-ScriptInfo -ScriptPath $_.FullName
    }
    
    Write-Status "Found $($scripts.Count) scripts"
    
    $outputFullPath = Join-Path $PSScriptRoot $OutputPath
    Export-Dashboard -Scripts $scripts -Path $outputFullPath
    
    if ($OpenAfter) {
        Start-Process $outputFullPath
    }
    
    Write-Success "Dashboard generation complete!"
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
