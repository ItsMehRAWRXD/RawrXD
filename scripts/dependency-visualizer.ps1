# RawrXD Dependency Visualizer
# Generates visual dependency graphs and reports for the codebase

param(
    [string]$SourceDir = "D:\rawrxd\src",
    [string]$OutputDir = "analysis/dependencies",
    [ValidateSet("graphviz", "mermaid", "json", "html", "all")]
    [string]$Format = "html",
    [switch]$IncludeExternal,
    [switch]$IncludeSystem,
    [int]$MaxDepth = 5,
    [string[]]$FocusModules = @(),
    [switch]$FindCircular,
    [switch]$ShowStats
)

$ErrorActionPreference = "Stop"

$script:DepState = @{
    StartTime = Get-Date
    FilesAnalyzed = 0
    DependenciesFound = 0
    CircularDeps = @()
    ModuleGraph = @{}
}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }

function Initialize-Visualizer {
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
}

function Get-IncludeDependencies {
    param([string]$FilePath)
    
    $content = Get-Content $FilePath -Raw -ErrorAction SilentlyContinue
    if (-not $content) { return @() }
    
    $includes = @()
    
    # Match #include statements
    $patterns = @(
        '#include\s*["<]([^">]+)[">]',  # Standard includes
        '#import\s*["<]([^">]+)[">]'    # Objective-C imports
    )
    
    foreach ($pattern in $patterns) {
        $matches = [regex]::Matches($content, $pattern)
        foreach ($match in $matches) {
            $include = $match.Groups[1].Value.Trim()
            
            # Skip system headers unless requested
            if (-not $IncludeSystem -and ($include -match "^(windows|sys|stdlib|stdio|iostream|vector|string|map|set|algorithm|memory|thread|mutex)")) {
                continue
            }
            
            $includes += $include
        }
    }
    
    return $includes | Select-Object -Unique
}

function Build-DependencyGraph {
    Write-Status "Building dependency graph..."
    
    $graph = @{}
    $sourceFiles = Get-ChildItem -Path $SourceDir -Recurse -File | 
        Where-Object { $_.Extension -in @(".cpp", ".c", ".h", ".hpp", ".cc") }
    
    if ($FocusModules.Count -gt 0) {
        $sourceFiles = $sourceFiles | Where-Object { 
            $fileName = $_.Name
            $FocusModules | Where-Object { $fileName -like "*$_*" }
        }
    }
    
    $totalFiles = $sourceFiles.Count
    $processed = 0
    
    foreach ($file in $sourceFiles) {
        $processed++
        if ($processed % 100 -eq 0) {
            Write-Progress -Activity "Analyzing dependencies" -Status "$processed/$totalFiles files" -PercentComplete (($processed / $totalFiles) * 100)
        }
        
        $relativePath = $file.FullName.Replace($SourceDir, "").TrimStart("\")
        $includes = Get-IncludeDependencies -FilePath $file.FullName
        
        $graph[$relativePath] = @{
            FullPath = $file.FullName
            Includes = $includes
            IncludedBy = @()
            Depth = 0
            Module = ($relativePath -split "\\")[0]
        }
        
        $script:DepState.FilesAnalyzed++
        $script:DepState.DependenciesFound += $includes.Count
    }
    
    Write-Progress -Activity "Analyzing dependencies" -Completed
    
    # Build reverse dependencies
    foreach ($file in $graph.Keys) {
        foreach ($include in $graph[$file].Includes) {
            # Find which file provides this include
            $provider = $graph.Keys | Where-Object { 
                $_ -like "*$include" -or $_ -replace "\\", "/" -like "*$include"
            } | Select-Object -First 1
            
            if ($provider -and $graph.ContainsKey($provider)) {
                if (-not $graph[$provider].IncludedBy.Contains($file)) {
                    $graph[$provider].IncludedBy += $file
                }
            }
        }
    }
    
    # Calculate depth
    Calculate-Depths -Graph $graph
    
    $script:DepState.ModuleGraph = $graph
    Write-Success "Dependency graph built: $($graph.Count) files, $($script:DepState.DependenciesFound) dependencies"
    
    return $graph
}

function Calculate-Depths {
    param([hashtable]$Graph)
    
    $visited = @{}
    $recStack = @{}
    
    function Visit-Node {
        param([string]$Node, [int]$CurrentDepth)
        
        if ($recStack[$Node]) {
            # Circular dependency detected
            $script:DepState.CircularDeps += $Node
            return $CurrentDepth
        }
        
        if ($visited[$Node]) {
            return $Graph[$Node].Depth
        }
        
        $visited[$Node] = $true
        $recStack[$Node] = $true
        
        $maxChildDepth = $CurrentDepth
        foreach ($dep in $Graph[$Node].Includes) {
            $depNode = $Graph.Keys | Where-Object { $_ -like "*$dep" } | Select-Object -First 1
            if ($depNode -and $Graph.ContainsKey($depNode)) {
                $childDepth = Visit-Node -Node $depNode -CurrentDepth ($CurrentDepth + 1)
                $maxChildDepth = [Math]::Max($maxChildDepth, $childDepth)
            }
        }
        
        $recStack[$Node] = $false
        $Graph[$Node].Depth = $maxChildDepth
        
        return $maxChildDepth
    }
    
    foreach ($node in $Graph.Keys) {
        if (-not $visited[$node]) {
            Visit-Node -Node $node -CurrentDepth 0
        }
    }
}

function Find-CircularDependencies {
    param([hashtable]$Graph)
    
    if (-not $FindCircular) { return @() }
    
    Write-Status "Searching for circular dependencies..."
    
    $circular = @()
    $visited = @{}
    $recStack = @{}
    $path = @()
    
    function DFS {
        param([string]$Node)
        
        $visited[$Node] = $true
        $recStack[$Node] = $true
        $path += $Node
        
        foreach ($dep in $Graph[$Node].Includes) {
            $depNode = $Graph.Keys | Where-Object { $_ -like "*$dep" } | Select-Object -First 1
            
            if (-not $depNode -or -not $Graph.ContainsKey($depNode)) { continue }
            
            if (-not $visited[$depNode]) {
                DFS -Node $depNode
            } elseif ($recStack[$depNode]) {
                # Circular dependency found
                $cycleStart = $path.IndexOf($depNode)
                $cycle = $path[$cycleStart..($path.Count - 1)]
                $circular += @{ Cycle = $cycle; Length = $cycle.Count }
            }
        }
        
        $recStack[$Node] = $false
        $path = $path[0..($path.Count - 2)]
    }
    
    foreach ($node in $Graph.Keys) {
        if (-not $visited[$node]) {
            DFS -Node $node
        }
    }
    
    $script:DepState.CircularDeps = $circular
    
    if ($circular.Count -gt 0) {
        Write-Warning "Found $($circular.Count) circular dependencies"
    } else {
        Write-Success "No circular dependencies found"
    }
    
    return $circular
}

function Generate-GraphvizOutput {
    param([hashtable]$Graph)
    
    $dot = "digraph RawrXD_Dependencies {`n"
    $dot += "    rankdir=TB;`n"
    $dot += "    node [shape=box, style=filled, fillcolor=lightblue];`n"
    $dot += "    edge [color=gray];`n"
    $dot += "`n"
    
    # Group by module
    $modules = $Graph.Values | Group-Object -Property Module
    
    foreach ($module in $modules) {
        $dot += "    subgraph cluster_$($module.Name) {`n"
        $dot += "        label=`"$($module.Name)`";`n"
        $dot += "        style=filled;`n"
        $dot += "        fillcolor=lightyellow;`n"
        
        foreach ($file in $module.Group) {
            $nodeName = ($file.FullPath.Replace($SourceDir, "").Replace("\", "_").Replace(".", "_")).TrimStart("_")
            $label = [System.IO.Path]::GetFileName($file.FullPath)
            $dot += "        `"$nodeName`" [label=`"$label`"];`n"
        }
        
        $dot += "    }`n"
    }
    
    $dot += "`n"
    
    # Add edges
    foreach ($file in $Graph.Keys) {
        $sourceNode = ($Graph[$file].FullPath.Replace($SourceDir, "").Replace("\", "_").Replace(".", "_")).TrimStart("_")
        
        foreach ($include in $Graph[$file].Includes) {
            $targetFile = $Graph.Keys | Where-Object { $_ -like "*$include" } | Select-Object -First 1
            if ($targetFile) {
                $targetNode = ($Graph[$targetFile].FullPath.Replace($SourceDir, "").Replace("\", "_").Replace(".", "_")).TrimStart("_")
                $dot += "    `"$sourceNode`" -> `"$targetNode`";`n"
            }
        }
    }
    
    $dot += "}"
    
    $outputFile = "$OutputDir\dependencies.dot"
    $dot | Out-File $outputFile -Encoding UTF8
    
    Write-Success "Graphviz DOT file generated: $outputFile"
    Write-Host "  Convert to PNG: dot -Tpng $outputFile -o dependencies.png" -ForegroundColor Gray
    
    return $outputFile
}

function Generate-MermaidOutput {
    param([hashtable]$Graph)
    
    $mermaid = "graph TD`n"
    
    # Add nodes (limit to avoid huge diagrams)
    $limitedGraph = $Graph.Keys | Select-Object -First 100
    
    foreach ($file in $limitedGraph) {
        $nodeId = ($file -replace "[^a-zA-Z0-9]", "_")
        $label = [System.IO.Path]::GetFileName($file)
        $mermaid += "    $nodeId[$label]`n"
    }
    
    $mermaid += "`n"
    
    # Add edges
    foreach ($file in $limitedGraph) {
        $sourceId = ($file -replace "[^a-zA-Z0-9]", "_")
        
        foreach ($include in $Graph[$file].Includes | Select-Object -First 5) {
            $targetFile = $Graph.Keys | Where-Object { $_ -like "*$include" } | Select-Object -First 1
            if ($targetFile -and ($limitedGraph -contains $targetFile)) {
                $targetId = ($targetFile -replace "[^a-zA-Z0-9]", "_")
                $mermaid += "    $sourceId --> $targetId`n"
            }
        }
    }
    
    $outputFile = "$OutputDir\dependencies.mmd"
    $mermaid | Out-File $outputFile -Encoding UTF8
    
    Write-Success "Mermaid diagram generated: $outputFile"
    
    return $outputFile
}

function Generate-HtmlVisualization {
    param([hashtable]$Graph)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD Dependency Visualization</title>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1400px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        h1 { color: #333; }
        #graph { width: 100%; height: 800px; border: 1px solid #ddd; border-radius: 4px; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin: 20px 0; }
        .stat-card { background: #f8f9fa; padding: 15px; border-radius: 8px; text-align: center; }
        .stat-value { font-size: 2em; font-weight: bold; color: #667eea; }
        .stat-label { color: #666; margin-top: 5px; }
        .controls { margin: 20px 0; }
        button { padding: 10px 20px; margin-right: 10px; border: none; border-radius: 4px; cursor: pointer; }
        .btn-primary { background: #667eea; color: white; }
        .btn-secondary { background: #e9ecef; color: #333; }
    </style>
</head>
<body>
    <div class="container">
        <h1>RawrXD Dependency Graph</h1>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-value">$($Graph.Count)</div>
                <div class="stat-label">Files</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">$($script:DepState.DependenciesFound)</div>
                <div class="stat-label">Dependencies</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">$($script:DepState.CircularDeps.Count)</div>
                <div class="stat-label">Circular Dependencies</div>
            </div>
            <div class="stat-card">
                <div class="stat-value">$(($Graph.Values | Measure-Object -Property Depth -Maximum).Maximum)</div>
                <div class="stat-label">Max Depth</div>
            </div>
        </div>
        
        <div class="controls">
            <button class="btn-primary" onclick="resetZoom()">Reset View</button>
            <button class="btn-secondary" onclick="toggleLabels()">Toggle Labels</button>
        </div>
        
        <div id="graph"></div>
    </div>
    
    <script>
        // D3.js force-directed graph would go here
        // For now, showing a placeholder
        document.getElementById('graph').innerHTML = 
            '<div style="display: flex; justify-content: center; align-items: center; height: 100%; color: #666;">' +
            '<p>Interactive D3.js visualization would render here.<br>' +
            'Use Graphviz output for static visualization.</p></div>';
    </script>
</body>
</html>
"@
    
    $outputFile = "$OutputDir\dependency-visualization.html"
    $html | Out-File $outputFile -Encoding UTF8
    
    Write-Success "HTML visualization generated: $outputFile"
    
    return $outputFile
}

function Generate-DependencyReport {
    param([hashtable]$Graph, [array]$Circular)
    
    $report = @{
        Timestamp = Get-Date -Format "o"
        Summary = @{
            TotalFiles = $Graph.Count
            TotalDependencies = $script:DepState.DependenciesFound
            CircularDependencies = $Circular.Count
            MaxDepth = ($Graph.Values | Measure-Object -Property Depth -Maximum).Maximum
            AverageDependencies = [math]::Round($script:DepState.DependenciesFound / $Graph.Count, 2)
        }
        Modules = ($Graph.Values | Group-Object -Property Module | ForEach-Object {
            @{
                Name = $_.Name
                FileCount = $_.Count
                Dependencies = ($_.Group | ForEach-Object { $_.Includes.Count } | Measure-Object -Sum).Sum
            }
        })
        MostDependedOn = ($Graph.Values | Sort-Object IncludedBy.Count -Descending | Select-Object -First 10 | ForEach-Object {
            @{
                File = ($_.FullPath.Replace("$SourceDir\", ""))
                ReferencedBy = $_.IncludedBy.Count
            }
        })
        CircularDependencies = $Circular
        OrphanFiles = ($Graph.Keys | Where-Object { $Graph[$_].Includes.Count -eq 0 -and $Graph[$_].IncludedBy.Count -eq 0 })
    }
    
    $outputFile = "$OutputDir\dependency-report.json"
    $report | ConvertTo-Json -Depth 10 | Out-File $outputFile
    
    Write-Success "Dependency report generated: $outputFile"
    
    return $report
}

function Show-DependencyStats {
    param([hashtable]$Graph)
    
    if (-not $ShowStats) { return }
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Dependency Statistics" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    # Module breakdown
    Write-Host "Modules:" -ForegroundColor White
    $modules = $Graph.Values | Group-Object -Property Module | Sort-Object Count -Descending
    foreach ($module in $modules | Select-Object -First 10) {
        Write-Host "  $($module.Name): $($module.Count) files" -ForegroundColor Gray
    }
    
    Write-Host ""
    
    # Most depended on
    Write-Host "Most Referenced Files:" -ForegroundColor White
    $mostReferenced = $Graph.Values | Sort-Object { $_.IncludedBy.Count } -Descending | Select-Object -First 10
    foreach ($file in $mostReferenced) {
        $relativePath = $file.FullPath.Replace($SourceDir, "").TrimStart("\")
        Write-Host "  $($file.IncludedBy.Count) refs: $relativePath" -ForegroundColor Gray
    }
    
    Write-Host ""
    
    # Depth distribution
    Write-Host "Dependency Depth Distribution:" -ForegroundColor White
    $depths = $Graph.Values | Group-Object -Property Depth | Sort-Object Name
    foreach ($depth in $depths) {
        $bar = "█" * [math]::Min($depth.Count, 50)
        Write-Host "  Depth $($depth.Name): $bar ($($depth.Count))" -ForegroundColor Gray
    }
    
    Write-Host ""
    
    # Orphan files
    $orphans = $Graph.Keys | Where-Object { $Graph[$_].Includes.Count -eq 0 -and $Graph[$_].IncludedBy.Count -eq 0 }
    if ($orphans.Count -gt 0) {
        Write-Warning "Found $($orphans.Count) orphan files (no includes, not included)"
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Dependency Visualizer" -ForegroundColor Cyan
    Write-Host "===========================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-Visualizer
    
    # Build graph
    $graph = Build-DependencyGraph
    
    # Find circular dependencies
    $circular = Find-CircularDependencies -Graph $graph
    
    # Generate outputs
    switch ($Format) {
        "graphviz" { Generate-GraphvizOutput -Graph $graph }
        "mermaid" { Generate-MermaidOutput -Graph $graph }
        "html" { Generate-HtmlVisualization -Graph $graph }
        "json" { Generate-DependencyReport -Graph $graph -Circular $circular }
        "all" {
            Generate-GraphvizOutput -Graph $graph
            Generate-MermaidOutput -Graph $graph
            Generate-HtmlVisualization -Graph $graph
            Generate-DependencyReport -Graph $graph -Circular $circular
        }
    }
    
    # Show statistics
    Show-DependencyStats -Graph $graph
    
    Write-Host ""
    Write-Success "Dependency visualization complete!"
}

Main
