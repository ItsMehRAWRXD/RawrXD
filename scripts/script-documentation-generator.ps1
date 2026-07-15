# RawrXD Script Documentation Generator
# Generates comprehensive documentation from script comments
# Version: 1.0.0
# Author: RawrXD DevOps Team

param(
    [Parameter()]
    [string]$OutputPath = "docs",
    
    [Parameter()]
    [ValidateSet("Markdown", "HTML", "PDF", "All")]
    [string]$Format = "Markdown",
    
    [Parameter()]
    [switch]$IncludeExamples,
    
    [Parameter()]
    [switch]$IncludeSource,
    
    [Parameter()]
    [switch]$OpenAfter
)

$ErrorActionPreference = "Stop"
$script:Version = "1.0.0"

function Write-Status { param([string]$Message) Write-Host "[INFO] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[OK] $Message" -ForegroundColor Green }

function Get-ScriptDocumentation {
    param([string]$ScriptPath)
    
    $content = Get-Content $ScriptPath -Raw
    $fileName = [System.IO.Path]::GetFileNameWithoutExtension($ScriptPath)
    
    # Extract help comment block
    $helpMatch = [regex]::Match($content, '<#(.+?)#>', [System.Text.RegularExpressions.RegexOptions]::Singleline)
    $helpContent = if ($helpMatch.Success) { $helpMatch.Groups[1].Value } else { "" }
    
    $doc = [PSCustomObject]@{
        Name = $fileName
        Synopsis = ""
        Description = ""
        Parameters = @()
        Examples = @()
        Notes = ""
        Inputs = ""
        Outputs = ""
        Version = "1.0.0"
        Author = "RawrXD Team"
    }
    
    # Parse help sections
    if ($helpContent) {
        # Synopsis
        if ($helpContent -match '\.SYNOPSIS\s*(.+?)(?=\.|\z)') {
            $doc.Synopsis = $matches[1].Trim()
        }
        
        # Description
        if ($helpContent -match '\.DESCRIPTION\s*(.+?)(?=\.|\z)') {
            $doc.Description = $matches[1].Trim()
        }
        
        # Parameters
        $paramMatches = [regex]::Matches($helpContent, '\.PARAMETER\s+(\w+)\s*(.+?)(?=\.|\z)')
        foreach ($match in $paramMatches) {
            $doc.Parameters += [PSCustomObject]@{
                Name = $match.Groups[1].Value
                Description = $match.Groups[2].Value.Trim()
            }
        }
        
        # Examples
        $exampleMatches = [regex]::Matches($helpContent, '\.EXAMPLE\s*(.+?)(?=\.|\z)')
        foreach ($match in $exampleMatches) {
            $doc.Examples += $match.Groups[1].Value.Trim()
        }
        
        # Notes
        if ($helpContent -match '\.NOTES\s*(.+?)(?=\.|\z)') {
            $doc.Notes = $matches[1].Trim()
        }
        
        # Inputs
        if ($helpContent -match '\.INPUTS\s*(.+?)(?=\.|\z)') {
            $doc.Inputs = $matches[1].Trim()
        }
        
        # Outputs
        if ($helpContent -match '\.OUTPUTS\s*(.+?)(?=\.|\z)') {
            $doc.Outputs = $matches[1].Trim()
        }
    }
    
    # Extract inline metadata
    if ($content -match '#\s*Version:\s*(.+)') {
        $doc.Version = $matches[1].Trim()
    }
    if ($content -match '#\s*Author:\s*(.+)') {
        $doc.Author = $matches[1].Trim()
    }
    
    return $doc
}

function Export-MarkdownDocumentation {
    param([array]$Documents, [string]$OutputDir)
    
    if (-not (Test-Path $OutputDir)) {
        New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
    }
    
    # Generate index
    $index = "# RawrXD Script Documentation`n`n"
    $index += "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')`n`n"
    $index += "## Script Reference`n`n"
    
    foreach ($doc in ($Documents | Sort-Object Name)) {
        $index += "- [$($doc.Name)]($($doc.Name).md)`n"
    }
    
    $index | Set-Content (Join-Path $OutputDir "index.md") -Encoding UTF8
    
    # Generate individual docs
    foreach ($doc in $Documents) {
        $md = "# $($doc.Name)`n`n"
        $md += "**Version:** $($doc.Version)  `n"
        $md += "**Author:** $($doc.Author)`n`n"
        
        if ($doc.Synopsis) {
            $md += "## Synopsis`n`n"
            $md += "$($doc.Synopsis)`n`n"
        }
        
        if ($doc.Description) {
            $md += "## Description`n`n"
            $md += "$($doc.Description)`n`n"
        }
        
        if ($doc.Parameters.Count -gt 0) {
            $md += "## Parameters`n`n"
            foreach ($param in $doc.Parameters) {
                $md += "### -$($param.Name)`n`n"
                $md += "$($param.Description)`n`n"
            }
        }
        
        if ($IncludeExamples -and $doc.Examples.Count -gt 0) {
            $md += "## Examples`n`n"
            $i = 1
            foreach ($example in $doc.Examples) {
                $md += "### Example $i`n`n"
                $md += "```powershell`n$example`n````n`n"
                $i++
            }
        }
        
        if ($doc.Inputs) {
            $md += "## Inputs`n`n"
            $md += "$($doc.Inputs)`n`n"
        }
        
        if ($doc.Outputs) {
            $md += "## Outputs`n`n"
            $md += "$($doc.Outputs)`n`n"
        }
        
        if ($doc.Notes) {
            $md += "## Notes`n`n"
            $md += "$($doc.Notes)`n`n"
        }
        
        $md | Set-Content (Join-Path $OutputDir "$($doc.Name).md") -Encoding UTF8
    }
    
    Write-Success "Markdown documentation generated in: $OutputDir"
}

function Export-HTMLDocumentation {
    param([array]$Documents, [string]$OutputDir)
    {
        # Implementation for HTML export
        Write-Status "HTML documentation generation would be implemented here"
    }
}

# Main execution
try {
    Write-Status "Generating script documentation..."
    
    $scripts = Get-ChildItem -Path $PSScriptRoot -Filter "*.ps1"
    $documents = @()
    
    foreach ($script in $scripts) {
        $doc = Get-ScriptDocumentation -ScriptPath $script.FullName
        $documents += $doc
    }
    
    Write-Status "Processed $($documents.Count) scripts"
    
    $outputFullPath = Join-Path $PSScriptRoot $OutputPath
    
    switch ($Format) {
        "Markdown" { Export-MarkdownDocumentation -Documents $documents -OutputDir $outputFullPath }
        "HTML" { Export-HTMLDocumentation -Documents $documents -OutputDir $outputFullPath }
        "All" {
            Export-MarkdownDocumentation -Documents $documents -OutputDir "$outputFullPath\markdown"
            Export-HTMLDocumentation -Documents $documents -OutputDir "$outputFullPath\html"
        }
    }
    
    if ($OpenAfter) {
        Start-Process $outputFullPath
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
