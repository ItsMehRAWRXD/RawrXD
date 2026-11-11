# RawrXD Prompt Engineer
# Tools for prompt engineering and optimization

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("Optimize", "Analyze", "Template", "Compare", "Batch")]
    [string]$Action = "Optimize",
    
    [string]$Prompt = "",
    [string]$PromptFile = "",
    [string]$OutputFile = "",
    [string]$TemplateName = "",
    [ValidateSet("concise", "detailed", "creative", "technical")]
    [string]$Style = "concise",
    [switch]$Interactive
)

$ErrorActionPreference = "Stop"

$script:TemplatesDir = "prompts/templates"

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

function Write-Warning {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

function Initialize-PromptEngineer {
    if (-not (Test-Path $script:TemplatesDir)) {
        New-Item -ItemType Directory -Path $script:TemplatesDir -Force | Out-Null
    }
    
    Write-Status "Prompt Engineer initialized"
}

function Get-PromptTemplates {
    return @{
        "code-review" = @{
            Name = "Code Review"
            Template = "Please review the following code for potential issues, improvements, and best practices. Focus on: performance, security, readability, and maintainability.`n`n```code`n{{PROMPT}}`n```"
            Description = "Professional code review template"
        }
        "explain-like-im-five" = @{
            Name = "Explain Like I'm 5"
            Template = "Explain the following concept in simple terms that a 5-year-old would understand. Use analogies and simple examples.`n`nTopic: {{PROMPT}}"
            Description = "Simplified explanation for beginners"
        }
        "step-by-step" = @{
            Name = "Step-by-Step Guide"
            Template = "Provide a detailed step-by-step guide for: {{PROMPT}}`n`nInclude:`n1. Prerequisites`n2. Step-by-step instructions`n3. Common pitfalls to avoid`n4. Tips for success"
            Description = "Structured instructional guide"
        }
        "pros-cons" = @{
            Name = "Pros and Cons Analysis"
            Template = "Analyze the following topic and provide a balanced view of pros and cons:`n`nTopic: {{PROMPT}}`n`nFormat your response as:`n## Pros`n- [advantage 1]`n- [advantage 2]`n`n## Cons`n- [disadvantage 1]`n- [disadvantage 2]`n`n## Recommendation"
            Description = "Balanced decision-making analysis"
        }
        "creative-story" = @{
            Name = "Creative Story"
            Template = "Write a creative story based on the following prompt. Make it engaging with vivid descriptions and interesting characters.`n`nPrompt: {{PROMPT}}`n`nStyle: Narrative fiction with descriptive language"
            Description = "Creative writing prompt"
        }
        "technical-doc" = @{
            Name = "Technical Documentation"
            Template = "Create technical documentation for: {{PROMPT}}`n`nInclude:`n- Overview`n- API Reference (if applicable)`n- Usage Examples`n- Configuration Options`n- Troubleshooting"
            Description = "Professional technical documentation"
        }
        "bug-report" = @{
            Name = "Bug Report Analysis"
            Template = "Analyze the following bug report and provide:`n1. Potential root causes`n2. Suggested debugging steps`n3. Possible solutions`n4. Prevention recommendations`n`nBug Report: {{PROMPT}}"
            Description = "Structured bug analysis"
        }
        "refactor" = @{
            Name = "Code Refactoring"
            Template = "Refactor the following code to improve:`n- Readability`n- Performance`n- Maintainability`n- Best practices adherence`n`nOriginal Code:`n```code`n{{PROMPT}}`n````n`nProvide the refactored code with explanations of changes."
            Description = "Code improvement suggestions"
        }
    }
}

function Optimize-PromptText {
    param([string]$InputPrompt, [string]$OptimizationStyle)
    
    Write-Status "Optimizing prompt for $OptimizationStyle style..."
    
    $optimized = $InputPrompt
    
    switch ($OptimizationStyle) {
        "concise" {
            $optimized = "Be brief and direct. $InputPrompt`n`nProvide only essential information."
        }
        "detailed" {
            $optimized = "Provide a comprehensive and detailed response. $InputPrompt`n`nInclude:`n- Background context`n- Detailed explanations`n- Examples where relevant`n- Edge cases and considerations"
        }
        "creative" {
            $optimized = "Be creative and imaginative. $InputPrompt`n`nFeel free to:`n- Use metaphors and analogies`n- Think outside the box`n- Provide multiple perspectives`n- Include creative examples"
        }
        "technical" {
            $optimized = "Provide a technical and precise response. $InputPrompt`n`nRequirements:`n- Use technical terminology appropriately`n- Include code examples if relevant`n- Reference standards or specifications`n- Be precise and accurate"
        }
    }
    
    return $optimized
}

function Show-PromptAnalysis {
    param([string]$InputPrompt)
    
    Write-Host ""
    Write-Host "Prompt Analysis" -ForegroundColor Cyan
    Write-Host "===============" -ForegroundColor Cyan
    Write-Host ""
    
    $wordCount = ($InputPrompt -split '\s+').Count
    $charCount = $InputPrompt.Length
    $lineCount = ($InputPrompt -split "`n").Count
    
    Write-Host "Statistics" -ForegroundColor Yellow
    Write-Host "  Words: $wordCount"
    Write-Host "  Characters: $charCount"
    Write-Host "  Lines: $lineCount"
    Write-Host ""
    
    # Check for common issues
    $issues = @()
    
    if ($wordCount -lt 5) {
        $issues += "Prompt is very short - may lack context"
    }
    if ($wordCount -gt 500) {
        $issues += "Prompt is very long - may exceed token limits"
    }
    if ($InputPrompt -notmatch '\?') {
        $issues += "No question mark - intent may be unclear"
    }
    if ($InputPrompt -cmatch '^[A-Z]') {
        $issues += "Prompt starts with lowercase - may be incomplete"
    }
    
    if ($issues.Count -gt 0) {
        Write-Host "Potential Issues" -ForegroundColor Yellow
        foreach ($issue in $issues) {
            Write-Host "  ⚠ $issue" -ForegroundColor Yellow
        }
    } else {
        Write-Success "No obvious issues detected"
    }
    
    Write-Host ""
    Write-Host "Suggestions" -ForegroundColor Green
    Write-Host "  • Be specific about the desired output format"
    Write-Host "  • Include relevant context"
    Write-Host "  • Specify constraints or requirements"
    Write-Host "  • Consider adding examples"
}

function Apply-PromptTemplate {
    param([string]$Template, [string]$Content)
    
    $templates = Get-PromptTemplates
    
    if (-not $templates[$Template]) {
        Write-Error "Template not found: $Template"
        Write-Host "Available templates:"
        foreach ($t in $templates.Keys) {
            Write-Host "  - $t"
        }
        return $null
    }
    
    $templateObj = $templates[$Template]
    $result = $templateObj.Template -replace "{{PROMPT}}", $Content
    
    Write-Success "Applied template: $($templateObj.Name)"
    return $result
}

function Show-TemplateList {
    $templates = Get-PromptTemplates
    
    Write-Host ""
    Write-Host "Available Templates" -ForegroundColor Cyan
    Write-Host "==================" -ForegroundColor Cyan
    Write-Host ""
    
    foreach ($template in $templates.GetEnumerator()) {
        Write-Host "  $($template.Key)" -ForegroundColor Green
        Write-Host "    $($template.Value.Name)"
        Write-Host "    $($template.Value.Description)"
        Write-Host ""
    }
}

function Compare-PromptVersions {
    param([string[]]$Prompts)
    
    Write-Host ""
    Write-Host "Prompt Comparison" -ForegroundColor Cyan
    Write-Host "=================" -ForegroundColor Cyan
    Write-Host ""
    
    $results = @()
    for ($i = 0; $i -lt $Prompts.Count; $i++) {
        $p = $Prompts[$i]
        $wordCount = ($p -split '\s+').Count
        $charCount = $p.Length
        
        $results += [PSCustomObject]@{
            Version = "V$($i + 1)"
            Words = $wordCount
            Characters = $charCount
            Preview = if ($p.Length -gt 50) { $p.Substring(0, 50) + "..." } else { $p }
        }
    }
    
    $results | Format-Table -AutoSize
}

function Process-PromptBatch {
    param([string]$FilePath)
    
    if (-not (Test-Path $FilePath)) {
        Write-Error "File not found: $FilePath"
        return
    }
    
    Write-Status "Processing batch prompts from: $FilePath"
    
    $prompts = Get-Content $FilePath | Where-Object { $_.Trim() -ne "" }
    $optimizedPrompts = @()
    
    $i = 1
    foreach ($p in $prompts) {
        Write-Status "Processing prompt $i/$($prompts.Count)..."
        $optimized = Optimize-PromptText -InputPrompt $p -OptimizationStyle $Style
        $optimizedPrompts += $optimized
        $i++
    }
    
    if ($OutputFile) {
        $optimizedPrompts | Out-File $OutputFile
        Write-Success "Optimized prompts saved to: $OutputFile"
    } else {
        Write-Host ""
        Write-Host "Optimized Prompts:" -ForegroundColor Cyan
        $optimizedPrompts | ForEach-Object { Write-Host "---`n$_`n" }
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Prompt Engineer" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host ""
    
    Initialize-PromptEngineer
    
    # Load prompt from file if specified
    if ($PromptFile -and (Test-Path $PromptFile)) {
        $Prompt = Get-Content $PromptFile -Raw
    }
    
    switch ($Action) {
        "Optimize" {
            if (-not $Prompt) {
                Write-Error "No prompt provided. Use -Prompt or -PromptFile"
                return
            }
            $optimized = Optimize-PromptText -InputPrompt $Prompt -OptimizationStyle $Style
            Write-Host ""
            Write-Host "Optimized Prompt:" -ForegroundColor Green
            Write-Host $optimized
            
            if ($OutputFile) {
                $optimized | Out-File $OutputFile
                Write-Success "Saved to: $OutputFile"
            }
        }
        "Analyze" {
            if (-not $Prompt) {
                Write-Error "No prompt provided"
                return
            }
            Show-PromptAnalysis -InputPrompt $Prompt
        }
        "Template" {
            if (-not $TemplateName) {
                Show-TemplateList
            } else {
                if (-not $Prompt) {
                    Write-Error "No content provided for template"
                    return
                }
                $result = Apply-PromptTemplate -Template $TemplateName -Content $Prompt
                if ($result) {
                    Write-Host ""
                    Write-Host "Result:" -ForegroundColor Green
                    Write-Host $result
                }
            }
        }
        "Compare" {
            if ($PromptFile) {
                $prompts = Get-Content $PromptFile | Where-Object { $_.Trim() -ne "" }
                Compare-PromptVersions -Prompts $prompts
            } else {
                Write-Error "Use -PromptFile with multiple prompts (one per line)"
            }
        }
        "Batch" {
            if (-not $PromptFile) {
                Write-Error "Batch mode requires -PromptFile"
                return
            }
            Process-PromptBatch -FilePath $PromptFile
        }
    }
    
    Write-Host ""
}

Main
