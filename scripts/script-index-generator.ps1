# RawrXD Script Index Generator
# Generates a searchable HTML index of all scripts with metadata
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [string]$OutputPath = "script-index.html",
    
    [Parameter()]
    [switch]$IncludeSource,
    
    [Parameter()]
    [switch]$OpenAfter,
    
    [Parameter()]
    [ValidateSet("HTML", "Markdown", "JSON", "CSV")]
    [string]$Format = "HTML"
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[WARN] $Message" -ForegroundColor Yellow }

function Get-ScriptMetadata {
    param([string]$ScriptPath)
    
    $content = Get-Content $ScriptPath -Raw -ErrorAction SilentlyContinue
    if (-not $content) { return $null }
    
    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($ScriptPath)
    $fileInfo = Get-Item $ScriptPath
    
    # Extract metadata from comments
    $version = if ($content -match "Version:\s*(.+)") { $matches[1].Trim() } else { "1.0.0" }
    $author = if ($content -match "Author:\s*(.+)") { $matches[1].Trim() } else { "RawrXD Team" }
    $description = if ($content -match "#\s*(.+?)(?:\r?\n|$)") { $matches[1].Trim() } else { "" }
    
    # Extract parameters
    $parameters = @()
    $paramMatches = [regex]::Matches($content, '\[Parameter\([^\]]*\)\]\s*\[?([^\]]+)\]?\s*\$([\w]+)')
    foreach ($match in $paramMatches) {
        $parameters += @{
            Type = $match.Groups[1].Value.Trim()
            Name = $match.Groups[2].Value
        }
    }
    
    # Categorize script
    $category = "Other"
    $lowerName = $fileName.ToLower()
    
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
    
    return [PSCustomObject]@{
        Name = $fileName
        Description = $description
        Version = $version
        Author = $author
        Category = $category
        Size = $fileInfo.Length
        Modified = $fileInfo.LastWriteTime
        Parameters = $parameters
        Path = $ScriptPath
    }
}

function Export-ScriptIndexHTML {
    param([array]$Scripts, [string]$OutputFile)
    
    $categories = $Scripts | Group-Object -Property Category | Sort-Object Name
    $totalScripts = $Scripts.Count
    $totalSize = ($Scripts | Measure-Object -Property Size -Sum).Sum
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RawrXD Script Index</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            line-height: 1.6;
            padding: 20px;
        }
        .container { max-width: 1400px; margin: 0 auto; }
        header {
            text-align: center;
            padding: 40px 0;
            border-bottom: 1px solid #30363d;
            margin-bottom: 30px;
        }
        h1 { color: #58a6ff; font-size: 2.5em; margin-bottom: 10px; }
        .subtitle { color: #8b949e; font-size: 1.1em; }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .stat-card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
            text-align: center;
        }
        .stat-value { font-size: 2em; color: #3fb950; font-weight: bold; }
        .stat-label { color: #8b949e; margin-top: 5px; }
        .search-box {
            width: 100%;
            padding: 15px;
            font-size: 16px;
            background: #21262d;
            border: 1px solid #30363d;
            border-radius: 8px;
            color: #c9d1d9;
            margin-bottom: 20px;
        }
        .search-box:focus {
            outline: none;
            border-color: #58a6ff;
        }
        .category {
            margin-bottom: 30px;
        }
        .category-header {
            background: #21262d;
            padding: 15px 20px;
            border-radius: 8px 8px 0 0;
            border: 1px solid #30363d;
            border-bottom: none;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .category-title {
            font-size: 1.3em;
            color: #58a6ff;
            font-weight: 600;
        }
        .category-count {
            background: #30363d;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.9em;
        }
        .script-list {
            border: 1px solid #30363d;
            border-radius: 0 0 8px 8px;
            overflow: hidden;
        }
        .script-item {
            background: #161b22;
            padding: 15px 20px;
            border-bottom: 1px solid #21262d;
            transition: background 0.2s;
        }
        .script-item:last-child { border-bottom: none; }
        .script-item:hover { background: #1c2128; }
        .script-name {
            font-family: 'Consolas', monospace;
            color: #d29922;
            font-size: 1.1em;
            margin-bottom: 5px;
        }
        .script-description {
            color: #8b949e;
            font-size: 0.95em;
            margin-bottom: 8px;
        }
        .script-meta {
            display: flex;
            gap: 15px;
            font-size: 0.85em;
            color: #6e7681;
        }
        .script-meta span {
            display: flex;
            align-items: center;
            gap: 5px;
        }
        .tag {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.75em;
            font-weight: 500;
        }
        .tag-version { background: #238636; color: white; }
        .tag-param { background: #1f6feb; color: white; }
        .hidden { display: none; }
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
    <div class="container">
        <header>
            <h1>🚀 RawrXD Script Index</h1>
            <p class="subtitle">Complete DevOps Automation Suite</p>
        </header>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">$totalScripts</div>
                <div class="stat-label">Total Scripts</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">$($categories.Count)</div>
                <div class="stat-label">Categories</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">$([math]::Round($totalSize / 1KB, 1)) KB</div>
                <div class="stat-label">Total Size</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">$(Get-Date -Format "yyyy-MM-dd")</div>
                <div class="stat-label">Generated</div>
            </div>
        </div>
        
        <input type="text" class="search-box" id="searchBox" 
               placeholder="Search scripts by name, description, or category...">
        
        <div id="scriptContainer">
"@

    foreach ($category in $categories) {
        $catName = $category.Name
        $catCount = $category.Count
        
        $html += @"
        <div class="category" data-category="$catName">
            <div class="category-header">
                <span class="category-title">$catName</span>
                <span class="category-count">$catCount scripts</span>
            </div>
            <div class="script-list">
"@
        
        foreach ($script in ($category.Group | Sort-Object Name)) {
            $paramCount = $script.Parameters.Count
            $paramTag = if ($paramCount -gt 0) { "<span class='tag tag-param'>$paramCount params</span>" } else { "" }
            $sizeKB = [math]::Round($script.Size / 1KB, 1)
            
            $html += @"
                <div class="script-item" data-name="$($script.Name)" data-desc="$($script.Description)">
                    <div class="script-name">$($script.Name).ps1 $paramTag <span class="tag tag-version">v$($script.Version)</span></div>
                    <div class="script-description">$($script.Description)</div>
                    <div class="script-meta">
                        <span>📄 $sizeKB KB</span>
                        <span>👤 $($script.Author)</span>
                        <span>🕐 $($script.Modified.ToString("yyyy-MM-dd"))</span>
                    </div>
                </div>
"@
        }
        
        $html += @"
            </div>
        </div>
"@
    }

    $html += @"
        </div>
        
        <footer>
            <p>RawrXD Vision & Generation System v3.2.0</p>
            <p>Generated by script-index-generator.ps1 v$script:Version</p>
        </footer>
    </div>
    
    <script>
        const searchBox = document.getElementById('searchBox');
        const scriptItems = document.querySelectorAll('.script-item');
        const categories = document.querySelectorAll('.category');
        
        searchBox.addEventListener('input', (e) => {
            const query = e.target.value.toLowerCase();
            
            scriptItems.forEach(item => {
                const name = item.dataset.name.toLowerCase();
                const desc = item.dataset.desc.toLowerCase();
                const match = name.includes(query) || desc.includes(query);
                item.classList.toggle('hidden', !match);
            });
            
            categories.forEach(cat => {
                const visibleItems = cat.querySelectorAll('.script-item:not(.hidden)');
                cat.style.display = visibleItems.length > 0 ? 'block' : 'none';
            });
        });
    </script>
</body>
</html>
"@

    $html | Set-Content $OutputFile -Encoding UTF8
    Write-Success "HTML index generated: $OutputFile"
}

function Export-ScriptIndexMarkdown {
    param([array]$Scripts, [string]$OutputFile)
    
    $categories = $Scripts | Group-Object -Property Category | Sort-Object Name
    
    $md = @"# RawrXD Script Index

Complete index of all PowerShell automation scripts for the RawrXD Vision & Generation System.

**Generated:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")  
**Total Scripts:** $($Scripts.Count)  
**Categories:** $($categories.Count)

## Table of Contents

"@

    foreach ($category in $categories) {
        $md += "- [$($category.Name)](#$(($category.Name -replace '\s+', '-').ToLower())) ($($category.Count) scripts)`n"
    }

    $md += "`n---`n"

    foreach ($category in $categories) {
        $md += "`n## $($category.Name)`n`n"
        $md += "| Script | Description | Version |`n"
        $md += "|--------|-------------|---------|`n"
        
        foreach ($script in ($category.Group | Sort-Object Name)) {
            $desc = if ($script.Description.Length -gt 60) { $script.Description.Substring(0, 60) + "..." } else { $script.Description }
            $md += "| ``$($script.Name).ps1`` | $desc | v$($script.Version) |`n"
        }
    }

    $md | Set-Content $OutputFile -Encoding UTF8
    Write-Success "Markdown index generated: $OutputFile"
}

function Export-ScriptIndexJSON {
    param([array]$Scripts, [string]$OutputFile)
    
    $index = @{
        GeneratedAt = (Get-Date).ToString("o")
        TotalScripts = $Scripts.Count
        Categories = @()
    }
    
    $categories = $Scripts | Group-Object -Property Category | Sort-Object Name
    foreach ($category in $categories) {
        $catObj = @{
            Name = $category.Name
            Count = $category.Count
            Scripts = @()
        }
        
        foreach ($script in ($category.Group | Sort-Object Name)) {
            $catObj.Scripts += @{
                Name = $script.Name
                Description = $script.Description
                Version = $script.Version
                Author = $script.Author
                Size = $script.Size
                Modified = $script.Modified.ToString("o")
                Parameters = $script.Parameters
            }
        }
        
        $index.Categories += $catObj
    }
    
    $index | ConvertTo-Json -Depth 5 | Set-Content $OutputFile -Encoding UTF8
    Write-Success "JSON index generated: $OutputFile"
}

function Export-ScriptIndexCSV {
    param([array]$Scripts, [string]$OutputFile)
    
    $csv = "Name,Category,Description,Version,Author,Size,Modified,ParameterCount`n"
    
    foreach ($script in ($Scripts | Sort-Object Category, Name)) {
        $desc = $script.Description -replace '"', '""'
        $csv += "`"$($script.Name)`",`"$($script.Category)`",`"$desc`",`"$($script.Version)`",`"$($script.Author)`",$($script.Size),`"$($script.Modified.ToString("yyyy-MM-dd"))`",$($script.Parameters.Count)`n"
    }
    
    $csv | Set-Content $OutputFile -Encoding UTF8
    Write-Success "CSV index generated: $OutputFile"
}

# Main execution
try {
    Write-Status "Scanning scripts in $PSScriptRoot..."
    
    $scripts = Get-ChildItem -Path $PSScriptRoot -Filter "*.ps1" | 
        Where-Object { $_.Name -ne "script-index-generator.ps1" } |
        ForEach-Object { Get-ScriptMetadata -ScriptPath $_.FullName } |
        Where-Object { $_ -ne $null }
    
    Write-Status "Found $($scripts.Count) scripts"
    
    $outputFullPath = Join-Path $PSScriptRoot $OutputPath
    
    switch ($Format) {
        "HTML" { Export-ScriptIndexHTML -Scripts $scripts -OutputFile $outputFullPath }
        "Markdown" { Export-ScriptIndexMarkdown -Scripts $scripts -OutputFile $outputFullPath }
        "JSON" { Export-ScriptIndexJSON -Scripts $scripts -OutputFile $outputFullPath }
        "CSV" { Export-ScriptIndexCSV -Scripts $scripts -OutputFile $outputFullPath }
    }
    
    if ($OpenAfter -and $Format -eq "HTML") {
        Start-Process $outputFullPath
    }
    
    Write-Success "Script index generation complete!"
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
