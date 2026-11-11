# RawrXD Documentation Generator
# Generates documentation from source code and configuration

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("API", "CLI", "Config", "All", "Markdown", "HTML")]
    [string]$DocType = "All",
    
    [string]$OutputPath = "docs/generated",
    [string]$SourcePath = "src",
    [switch]$IncludePrivate,
    [switch]$IncludeExamples,
    [string]$Template = "default",
    [switch]$Serve,
    [int]$Port = 8080
)

$ErrorActionPreference = "Stop"

$script:Stats = @{
    FilesProcessed = 0
    FunctionsDocumented = 0
    ClassesDocumented = 0
    PagesGenerated = 0
}

function Write-Status {
    param([string]$Message)
    Write-Host "[*] $Message" -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[✓] $Message" -ForegroundColor Green
}

function Write-Error {
    param([string]$Message)
    Write-Host "[✗] $Message" -ForegroundColor Red
}

function Initialize-DocGenerator {
    Write-Status "Documentation Generator initialized"
    Write-Status "Doc Type: $DocType"
    Write-Status "Output: $OutputPath"
    
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
        Write-Status "Created output directory: $OutputPath"
    }
}

function Get-SourceFiles {
    param([string]$Path, [string[]]$Extensions)
    
    $files = @()
    foreach ($ext in $Extensions) {
        $files += Get-ChildItem -Path $Path -Filter "*$ext" -Recurse -ErrorAction SilentlyContinue
    }
    return $files | Select-Object -Unique
}

function Extract-Comments {
    param([string]$Content, [string]$Language)
    
    $comments = @()
    
    switch ($Language) {
        "C++" {
            # Match /** */ style comments
            $pattern = '/\*\*(.*?)\*/'
            $matches = [regex]::Matches($Content, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
            foreach ($match in $matches) {
                $comment = $match.Groups[1].Value.Trim()
                $comments += $comment
            }
            
            # Match /// style comments
            $lines = $Content -split "`n"
            $currentComment = ""
            foreach ($line in $lines) {
                if ($line -match '^\s*///\s?(.*)$') {
                    $currentComment += $matches[1] + "`n"
                } elseif ($currentComment) {
                    $comments += $currentComment.Trim()
                    $currentComment = ""
                }
            }
        }
        "Python" {
            # Match """ style docstrings
            $pattern = '"""(.*?)"""'
            $matches = [regex]::Matches($Content, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
            foreach ($match in $matches) {
                $comments += $match.Groups[1].Value.Trim()
            }
        }
        "PowerShell" {
            # Match <# #> style comments
            $pattern = '<#(.*?)#>'
            $matches = [regex]::Matches($Content, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
            foreach ($match in $matches) {
                $comments += $match.Groups[1].Value.Trim()
            }
        }
    }
    
    return $comments
}

function Parse-FunctionDocumentation {
    param([string]$Comment)
    
    $doc = @{
        Summary = ""
        Parameters = @()
        Returns = ""
        Example = ""
    }
    
    # Extract summary
    if ($Comment -match '@brief\s+(.+)') {
        $doc.Summary = $matches[1].Trim()
    } elseif ($Comment -match '^\s*([^@\n]+)') {
        $doc.Summary = $matches[1].Trim()
    }
    
    # Extract parameters
    $paramMatches = [regex]::Matches($Comment, '@param\s+(\w+)\s+(.+)')
    foreach ($match in $paramMatches) {
        $doc.Parameters += @{
            Name = $match.Groups[1].Value
            Description = $match.Groups[2].Value.Trim()
        }
    }
    
    # Extract return value
    if ($Comment -match '@return\s+(.+)') {
        $doc.Returns = $matches[1].Trim()
    }
    
    # Extract example
    if ($Comment -match '@example\s+(.+?)(?=\n\s*@|\n\s*$|$)') {
        $doc.Example = $matches[1].Trim()
    }
    
    return $doc
}

function Generate-APIDocumentation {
    Write-Status "Generating API documentation..."
    
    $cppFiles = Get-SourceFiles -Path $SourcePath -Extensions @(".cpp", ".hpp", ".h")
    $apiDocs = @()
    
    foreach ($file in $cppFiles) {
        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }
        
        $comments = Extract-Comments -Content $content -Language "C++"
        
        foreach ($comment in $comments) {
            $doc = Parse-FunctionDocumentation -Comment $comment
            if ($doc.Summary) {
                $apiDocs += [PSCustomObject]@{
                    File = $file.Name
                    Summary = $doc.Summary
                    Parameters = $doc.Parameters
                    Returns = $doc.Returns
                    Example = $doc.Example
                }
                $script:FunctionsDocumented++
            }
        }
        
        $script:FilesProcessed++
    }
    
    # Generate markdown output
    $output = "# API Reference`n`n"
    $output += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n`n"
    $output += "---`n`n"
    
    foreach ($doc in $apiDocs) {
        $output += "## $($doc.File)`n`n"
        $output += "**Summary:** $($doc.Summary)`n`n"
        
        if ($doc.Parameters.Count -gt 0) {
            $output += "### Parameters`n`n"
            foreach ($param in $doc.Parameters) {
                $output += "- **$($param.Name)**: $($param.Description)`n"
            }
            $output += "`n"
        }
        
        if ($doc.Returns) {
            $output += "### Returns`n`n"
            $output += "$($doc.Returns)`n`n"
        }
        
        if ($doc.Example -and $IncludeExamples) {
            $output += "### Example`n`n"
            $output += "```cpp`n$($doc.Example)`n````n`n"
        }
        
        $output += "---`n`n"
    }
    
    $outputPath = "$OutputPath/api-reference.md"
    $output | Out-File -FilePath $outputPath -Encoding UTF8
    Write-Success "Generated API documentation: $outputPath"
    $script:PagesGenerated++
}

function Generate-CLIDocumentation {
    Write-Status "Generating CLI documentation..."
    
    # Extract CLI commands from source
    $cliDocs = @()
    
    # Look for CLI command definitions
    $cliFiles = Get-SourceFiles -Path $SourcePath -Extensions @(".cpp", ".c")
    
    foreach ($file in $cliFiles) {
        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }
        
        # Match command definitions (simplified pattern)
        $commandMatches = [regex]::Matches($content, 'add_argument\s*\(\s*"([^"]+)"\s*[^)]*\)')
        foreach ($match in $commandMatches) {
            $cliDocs += @{
                Command = $match.Groups[1].Value
                File = $file.Name
            }
        }
    }
    
    # Generate markdown
    $output = "# CLI Reference`n`n"
    $output += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n`n"
    $output += "## Commands`n`n"
    
    foreach ($cmd in $cliDocs | Select-Object -Unique) {
        $output += "### $($cmd.Command)`n`n"
        $output += "Defined in: ``$($cmd.File)``\n`n"
    }
    
    $outputPath = "$OutputPath/cli-reference.md"
    $output | Out-File -FilePath $outputPath -Encoding UTF8
    Write-Success "Generated CLI documentation: $outputPath"
    $script:PagesGenerated++
}

function Generate-ConfigDocumentation {
    Write-Status "Generating configuration documentation..."
    
    $configDocs = @()
    
    # Parse config files
    $configFiles = Get-ChildItem -Path "." -Filter "*.json" -ErrorAction SilentlyContinue | 
        Where-Object { $_.Name -like "*config*" -or $_.Name -like "*settings*" }
    
    foreach ($file in $configFiles) {
        try {
            $json = Get-Content $file.FullName | ConvertFrom-Json
            $configDocs += @{
                File = $file.Name
                Content = $json
            }
        }
        catch {
            Write-Warning "Failed to parse $($file.Name)"
        }
    }
    
    # Generate markdown
    $output = "# Configuration Reference`n`n"
    $output += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n`n"
    
    foreach ($config in $configDocs) {
        $output += "## $($config.File)`n`n"
        $output += "```json`n"
        $output += ($config.Content | ConvertTo-Json -Depth 3)
        $output += "`n```\n`n"
    }
    
    $outputPath = "$OutputPath/config-reference.md"
    $output | Out-File -FilePath $outputPath -Encoding UTF8
    Write-Success "Generated configuration documentation: $outputPath"
    $script:PagesGenerated++
}

function ConvertTo-HTML {
    Write-Status "Converting markdown to HTML..."
    
    $mdFiles = Get-ChildItem -Path $OutputPath -Filter "*.md"
    
    foreach ($mdFile in $mdFiles) {
        $content = Get-Content $mdFile.FullName -Raw
        $htmlContent = ConvertFrom-MarkdownToHTML -Markdown $content
        
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>$($mdFile.BaseName)</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1200px; margin: 0 auto; padding: 20px; }
        h1 { color: #333; border-bottom: 2px solid #0066cc; }
        h2 { color: #0066cc; }
        code { background: #f4f4f4; padding: 2px 5px; border-radius: 3px; }
        pre { background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }
    </style>
</head>
<body>
$htmlContent
</body>
</html>
"@
        
        $htmlPath = "$OutputPath/$($mdFile.BaseName).html"
        $html | Out-File -FilePath $htmlPath -Encoding UTF8
        Write-Success "Generated HTML: $htmlPath"
    }
}

function ConvertFrom-MarkdownToHTML {
    param([string]$Markdown)
    
    $html = $Markdown
    
    # Headers
    $html = $html -replace '^# (.+)$', '<h1>$1</h1>'
    $html = $html -replace '^## (.+)$', '<h2>$1</h2>'
    $html = $html -replace '^### (.+)$', '<h3>$1</h3>'
    
    # Code blocks
    $html = $html -replace '```(\w+)\n(.+?)\n```', '<pre><code class="language-$1">$2</code></pre>'
    $html = $html -replace '```\n(.+?)\n```', '<pre><code>$1</code></pre>'
    
    # Inline code
    $html = $html -replace '`([^`]+)`', '<code>$1</code>'
    
    # Bold
    $html = $html -replace '\*\*(.+?)\*\*', '<strong>$1</strong>'
    
    # Italic
    $html = $html -replace '\*(.+?)\*', '<em>$1</em>'
    
    # Line breaks
    $html = $html -replace "`n", "<br>"
    
    return $html
}

function Start-DocServer {
    Write-Status "Starting documentation server on port $Port..."
    
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add("http://localhost:$Port/")
    $listener.Start()
    
    Write-Success "Documentation server started at http://localhost:$Port/"
    Write-Status "Press Ctrl+C to stop"
    
    try {
        while ($listener.IsListening) {
            $context = $listener.GetContext()
            $request = $context.Request
            $response = $context.Response
            
            $path = $request.Url.LocalPath
            if ($path -eq "/") { $path = "/index.html" }
            
            $filePath = Join-Path $OutputPath $path.TrimStart('/')
            
            if (Test-Path $filePath) {
                $content = Get-Content $filePath -Raw -Encoding UTF8
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($content)
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            } else {
                $response.StatusCode = 404
                $message = "Not Found"
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($message)
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            }
            
            $response.Close()
        }
    }
    finally {
        $listener.Stop()
    }
}

function Show-Summary {
    Write-Host ""
    Write-Host "Documentation Generation Summary" -ForegroundColor Cyan
    Write-Host "===============================" -ForegroundColor Cyan
    Write-Host "Files processed: $($script:Stats.FilesProcessed)"
    Write-Host "Functions documented: $($script:Stats.FunctionsDocumented)"
    Write-Host "Classes documented: $($script:Stats.ClassesDocumented)"
    Write-Host "Pages generated: $($script:Stats.PagesGenerated)"
    Write-Host ""
    Write-Host "Output directory: $OutputPath" -ForegroundColor Green
}

# Main execution
function Main {
    Write-Host "RawrXD Documentation Generator" -ForegroundColor Cyan
    Write-Host "===============================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-DocGenerator
    
    switch ($DocType) {
        "API" { Generate-APIDocumentation }
        "CLI" { Generate-CLIDocumentation }
        "Config" { Generate-ConfigDocumentation }
        "All" {
            Generate-APIDocumentation
            Generate-CLIDocumentation
            Generate-ConfigDocumentation
        }
        "HTML" { ConvertTo-HTML }
        "Markdown" {
            Generate-APIDocumentation
            Generate-CLIDocumentation
            Generate-ConfigDocumentation
        }
    }
    
    Show-Summary
    
    if ($Serve) {
        Start-DocServer
    }
    
    Write-Host ""
}

Main
