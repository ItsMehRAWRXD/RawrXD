# RawrXD Documentation Generator
# Automated documentation generation from source code, READMEs, and configuration

param(
    [string]$SourceDir = "D:\rawrxd",
    [string]$OutputDir = "docs/generated",
    [ValidateSet("html", "markdown", "pdf", "all")]
    [string]$Format = "html",
    [switch]$IncludeApiDocs,
    [switch]$IncludeArchitecture,
    [switch]$IncludeChangelog,
    [switch]$IncludeWiki,
    [string]$Version = "3.2.0",
    [switch]$Serve,
    [int]$ServePort = 8080
)

$ErrorActionPreference = "Stop"

$script:DocState = @{
    StartTime = Get-Date
    GeneratedFiles = @()
    ApiEndpoints = @()
    Components = @()
}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }

function Initialize-Generator {
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
    
    # Create subdirectories
    $subdirs = @("api", "architecture", "guides", "reference")
    foreach ($dir in $subdirs) {
        $path = Join-Path $OutputDir $dir
        if (-not (Test-Path $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
    }
    
    Write-Success "Documentation directories initialized"
}

function Extract-ApiDocumentation {
    Write-Status "Extracting API documentation..."
    
    $apiDocs = @()
    $sourceFiles = Get-ChildItem -Path "$SourceDir\src" -Recurse -File -Filter "*.h" -ErrorAction SilentlyContinue
    $sourceFiles += Get-ChildItem -Path "$SourceDir\src" -Recurse -File -Filter "*.hpp" -ErrorAction SilentlyContinue
    
    foreach ($file in $sourceFiles) {
        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }
        
        # Extract functions with documentation
        $functions = [regex]::Matches($content, "/\*\*\s*([^*]|\*(?!/))*\*/\s*(\w+[\s*]+)+(\w+)\s*\([^)]*\)")
        
        foreach ($func in $functions) {
            $docComment = $func.Groups[0].Value
            $funcName = if ($func.Groups[3]) { $func.Groups[3].Value } else { "unknown" }
            
            # Parse documentation tags
            $brief = if ($docComment -match "@brief\s+(.+)") { $Matches[1].Trim() } else { "" }
            $param = if ($docComment -match "@param\s+(\w+)\s+(.+)") { @{ Name = $Matches[1]; Desc = $Matches[2] } } else { $null }
            $return = if ($docComment -match "@return\s+(.+)") { $Matches[1].Trim() } else { "" }
            
            $apiDocs += @{
                File = $file.FullName.Replace($SourceDir, "").TrimStart("\")
                Function = $funcName
                Brief = $brief
                Parameters = $param
                Returns = $return
            }
        }
    }
    
    $script:DocState.ApiEndpoints = $apiDocs
    Write-Success "Extracted $($apiDocs.Count) API endpoints"
    
    return $apiDocs
}

function Generate-ApiHtml {
    param([array]$ApiDocs)
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD API Reference</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #667eea; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .api-item { background: #f8f9fa; border-left: 4px solid #667eea; padding: 15px; margin: 15px 0; border-radius: 4px; }
        .function-name { font-family: 'Consolas', monospace; font-size: 1.2em; color: #667eea; font-weight: bold; }
        .file-path { color: #666; font-size: 0.9em; margin-bottom: 10px; }
        .brief { color: #333; margin: 10px 0; }
        .param { background: #e9ecef; padding: 5px 10px; border-radius: 3px; display: inline-block; margin: 5px 5px 5px 0; }
        .param-name { font-weight: bold; color: #495057; }
        .returns { color: #28a745; margin-top: 10px; }
        .nav { background: #333; padding: 15px; margin: -30px -30px 30px -30px; border-radius: 8px 8px 0 0; }
        .nav a { color: white; text-decoration: none; margin-right: 20px; }
        .nav a:hover { color: #667eea; }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="index.html">Overview</a>
            <a href="api-reference.html">API Reference</a>
            <a href="architecture.html">Architecture</a>
            <a href="guides.html">Guides</a>
        </div>
        
        <h1>RawrXD API Reference v$Version</h1>
        <p>Complete API documentation for the RawrXD Vision & Generation System.</p>
"@

    # Group by file
    $grouped = $ApiDocs | Group-Object -Property File
    
    foreach ($group in $grouped) {
        $html += "        <h2>$($group.Name)</h2>`n"
        
        foreach ($api in $group.Group) {
            $html += @"
        <div class="api-item">
            <div class="file-path">$($api.File)</div>
            <div class="function-name">$($api.Function)()</div>
            <div class="brief">$($api.Brief)</div>
"@
            if ($api.Parameters) {
                $html += "            <div class="param"><span class="param-name">$($api.Parameters.Name)</span>: $($api.Parameters.Desc)</div>`n"
            }
            if ($api.Returns) {
                $html += "            <div class="returns">Returns: $($api.Returns)</div>`n"
            }
            $html += "        </div>`n"
        }
    }
    
    $html += @"
    </div>
</body>
</html>
"@
    
    $outputFile = Join-Path $OutputDir "api\api-reference.html"
    $html | Out-File $outputFile -Encoding UTF8
    $script:DocState.GeneratedFiles += $outputFile
    
    Write-Success "API reference generated: $outputFile"
}

function Generate-ArchitectureDoc {
    Write-Status "Generating architecture documentation..."
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD Architecture</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 3px solid #667eea; padding-bottom: 10px; }
        h2 { color: #555; margin-top: 30px; }
        .component { background: #f8f9fa; border: 1px solid #dee2e6; padding: 20px; margin: 15px 0; border-radius: 8px; }
        .component h3 { margin-top: 0; color: #667eea; }
        .diagram { background: #e9ecef; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0; }
        .layer { background: white; border: 2px solid #667eea; padding: 15px; margin: 10px; border-radius: 5px; display: inline-block; min-width: 200px; }
        .arrow { font-size: 24px; color: #667eea; margin: 10px; }
        .nav { background: #333; padding: 15px; margin: -30px -30px 30px -30px; border-radius: 8px 8px 0 0; }
        .nav a { color: white; text-decoration: none; margin-right: 20px; }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="index.html">Overview</a>
            <a href="api-reference.html">API Reference</a>
            <a href="architecture.html">Architecture</a>
            <a href="guides.html">Guides</a>
        </div>
        
        <h1>RawrXD Architecture v$Version</h1>
        
        <h2>System Overview</h2>
        <p>RawrXD is a high-performance Vision & Generation System built on a modular architecture with the following key components:</p>
        
        <div class="diagram">
            <div class="layer"><strong>Application Layer</strong><br>Win32 IDE / CLI Tools</div><br>
            <div class="arrow">↓</div><br>
            <div class="layer"><strong>API Layer</strong><br>REST / gRPC / WebSocket</div><br>
            <div class="arrow">↓</div><br>
            <div class="layer"><strong>Core Engine</strong><br>GGML / Inference / Scheduling</div><br>
            <div class="arrow">↓</div><br>
            <div class="layer"><strong>Hardware Abstraction</strong><br>CUDA / Vulkan / CPU</div>
        </div>
        
        <h2>Core Components</h2>
        
        <div class="component">
            <h3>🧠 Inference Engine</h3>
            <p>The core GGML-based inference engine supporting multiple model formats (GGUF, GGML) with optimized kernels for CPU and GPU execution.</p>
            <ul>
                <li><strong>GGML Backend:</strong> Tensor operations and compute graph execution</li>
                <li><strong>Model Loader:</strong> GGUF/GGML format parsing and memory mapping</li>
                <li><strong>Scheduler:</strong> Batch processing and request queuing</li>
            </ul>
        </div>
        
        <div class="component">
            <h3>🎨 Vision Pipeline</h3>
            <p>Image generation and processing pipeline with support for diffusion models and VAE encoding/decoding.</p>
            <ul>
                <li><strong>Diffusion Core:</strong> UNet-based denoising and sampling</li>
                <li><strong>VAE:</strong> Latent space encoding/decoding</li>
                <li><strong>Post-processing:</strong> Upscaling and enhancement</li>
            </ul>
        </div>
        
        <div class="component">
            <h3>⚡ GPU Acceleration</h3>
            <p>Multi-backend GPU acceleration supporting CUDA, Vulkan, and Metal.</p>
            <ul>
                <li><strong>CUDA Backend:</strong> NVIDIA GPU acceleration</li>
                <li><strong>Vulkan Backend:</strong> Cross-platform GPU compute</li>
                <li><strong>Kernel Library:</strong> Optimized compute shaders</li>
            </ul>
        </div>
        
        <div class="component">
            <h3>🔧 Hotpatch System</strong></h3>
            <p>7-layer hotpatching architecture for runtime updates without service interruption.</p>
            <ul>
                <li>PT Driver Layer</li>
                <li>Memory Hotpatch Layer</li>
                <li>Byte-Level Patch Layer</li>
                <li>Server-Side Patch Layer</li>
                <li>Live Binary Patch Layer</li>
                <li>Shadow Page Layer</li>
                <li>Sentinel Monitor Layer</li>
            </ul>
        </div>
        
        <h2>Data Flow</h2>
        <p>1. <strong>Input Processing:</strong> Text prompts and parameters are validated and tokenized.</p>
        <p>2. <strong>Model Inference:</strong> The inference engine loads the appropriate model and executes the generation pipeline.</p>
        <p>3. <strong>Output Generation:</strong> Generated content is post-processed and returned to the caller.</p>
        
    </div>
</body>
</html>
"@
    
    $outputFile = Join-Path $OutputDir "architecture.html"
    $html | Out-File $outputFile -Encoding UTF8
    $script:DocState.GeneratedFiles += $outputFile
    
    Write-Success "Architecture documentation generated: $outputFile"
}

function Generate-IndexPage {
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD Documentation</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
        .container { max-width: 1000px; margin: 0 auto; padding: 50px 20px; }
        .hero { text-align: center; color: white; margin-bottom: 50px; }
        .hero h1 { font-size: 3.5em; margin-bottom: 20px; text-shadow: 2px 2px 4px rgba(0,0,0,0.3); }
        .hero p { font-size: 1.3em; opacity: 0.9; }
        .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }
        .card { background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 20px rgba(0,0,0,0.2); transition: transform 0.3s; text-decoration: none; color: #333; }
        .card:hover { transform: translateY(-5px); }
        .card h3 { color: #667eea; margin-top: 0; }
        .card-icon { font-size: 2.5em; margin-bottom: 15px; }
        .version { text-align: center; color: white; margin-top: 50px; opacity: 0.8; }
    </style>
</head>
<body>
    <div class="container">
        <div class="hero">
            <h1>🚀 RawrXD</h1>
            <p>Vision & Generation System Documentation</p>
        </div>
        
        <div class="cards">
            <a href="api-reference.html" class="card">
                <div class="card-icon">📚</div>
                <h3>API Reference</h3>
                <p>Complete API documentation with examples and usage guides.</p>
            </a>
            
            <a href="architecture.html" class="card">
                <div class="card-icon">🏗️</div>
                <h3>Architecture</h3>
                <p>System architecture, components, and design patterns.</p>
            </a>
            
            <a href="guides.html" class="card">
                <div class="card-icon">📖</div>
                <h3>Guides</h3>
                <p>Getting started, tutorials, and best practices.</p>
            </a>
            
            <a href="reference.html" class="card">
                <div class="card-icon">📋</div>
                <h3>Reference</h3>
                <p>Configuration options, CLI commands, and troubleshooting.</p>
            </a>
        </div>
        
        <div class="version">
            <p>Version $Version | Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')</p>
        </div>
    </div>
</body>
</html>
"@
    
    $outputFile = Join-Path $OutputDir "index.html"
    $html | Out-File $outputFile -Encoding UTF8
    $script:DocState.GeneratedFiles += $outputFile
    
    Write-Success "Index page generated: $outputFile"
}

function Start-DocServer {
    if (-not $Serve) { return }
    
    Write-Status "Starting documentation server on port $ServePort..."
    
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://localhost:$ServePort/")
    $listener.Start()
    
    Write-Success "Server running at http://localhost:$ServePort/"
    Write-Host "Press Ctrl+C to stop" -ForegroundColor Gray
    
    try {
        while ($listener.IsListening) {
            $context = $listener.GetContext()
            $request = $context.Request
            $response = $context.Response
            
            $path = $request.Url.LocalPath
            if ($path -eq "/") { $path = "/index.html" }
            
            $filePath = Join-Path $OutputDir $path.TrimStart("/")
            
            if (Test-Path $filePath) {
                $content = Get-Content $filePath -Raw -Encoding UTF8
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($content)
                $response.ContentType = "text/html"
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            } else {
                $response.StatusCode = 404
            }
            
            $response.Close()
        }
    } finally {
        $listener.Stop()
    }
}

function Export-DocumentationReport {
    $report = @{
        GeneratedAt = Get-Date -Format "o"
        Version = $Version
        FilesGenerated = $script:DocState.GeneratedFiles.Count
        Files = $script:DocState.GeneratedFiles
        ApiEndpoints = $script:DocState.ApiEndpoints.Count
    }
    
    $report | ConvertTo-Json -Depth 5 | Out-File (Join-Path $OutputDir "generation-report.json")
}

# Main execution
function Main {
    Write-Host "RawrXD Documentation Generator" -ForegroundColor Cyan
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-Generator
    
    # Generate API documentation
    if ($IncludeApiDocs) {
        $apiDocs = Extract-ApiDocumentation
        Generate-ApiHtml -ApiDocs $apiDocs
    }
    
    # Generate architecture documentation
    if ($IncludeArchitecture) {
        Generate-ArchitectureDoc
    }
    
    # Generate index page
    Generate-IndexPage
    
    # Export report
    Export-DocumentationReport
    
    Write-Host ""
    Write-Success "Documentation generation complete!"
    Write-Host "Generated $($script:DocState.GeneratedFiles.Count) files in $OutputDir" -ForegroundColor Gray
    
    # Start server if requested
    if ($Serve) {
        Write-Host ""
        Start-DocServer
    } else {
        Write-Host ""
        Write-Host "To view documentation, open $OutputDir\index.html in a browser" -ForegroundColor Cyan
        Write-Host "Or run with -Serve to start a local server" -ForegroundColor Gray
    }
}

Main
