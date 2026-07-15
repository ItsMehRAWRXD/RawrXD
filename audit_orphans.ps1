#Requires -Version 5.1
<#
.SYNOPSIS
    RawrXD Orphan Cluster Archaeology Tool
    Maps 275,698 orphaned files into resurrection candidates

.DESCRIPTION
    Phase 1: Kernel Archaeology
    Scans orphan directories for MASM/C++ compute kernels
    Generates ranked resurrection candidates

.PARAMETER Phase
    Which phase to run: Kernel, GPU, Loader, Build, ReverseEngineering

.PARAMETER OutputFormat
    CSV, JSON, or Markdown

.EXAMPLE
    .\audit_orphans.ps1 -Phase Kernel -OutputFormat CSV
#>

param(
    [Parameter(Mandatory=$true)]
    [ValidateSet("Kernel", "GPU", "Loader", "Build", "ReverseEngineering", "All")]
    [string]$Phase,

    [Parameter(Mandatory=$false)]
    [ValidateSet("CSV", "JSON", "Markdown")]
    [string]$OutputFormat = "CSV",

    [Parameter(Mandatory=$false)]
    [string]$OutputDir = ".\audit_results"
)

# Create output directory
if (-not (Test-Path $OutputDir)) {
    New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null
}

# Scoring weights
$ScoreWeights = @{
    ReferencedByActive = 5
    UniqueSymbols = 5
    OptimizedAssembly = 4
    GPUCode = 4
    HasTests = 3
    HasBuildFiles = 3
    RecentModification = 2
    MatchesArchitecture = 2
    GeneratedOutput = -5
    DuplicateHash = -5
    EmptyScaffold = -3
}

# Keywords for each phase
$PhaseKeywords = @{
    Kernel = @("kernel", "matmul", "gemm", "attention", "rope", "softmax", "quant", "q4", "q8", "avx", "avx2", "avx512", "fma", "tensor", "simd", "compute")
    GPU = @("vulkan", "cuda", "hip", "rocm", "shader", "spirv", "glsl", "hlsl", "gpu", "dma", "buffer", "command", "queue", "staging")
    Loader = @("gguf", "ggml", "loader", "tensor", "model", "tokenizer", "vocab", "metadata", "quant", "parse", "deserialize")
    Build = @("cmake", "ninja", "makefile", "vcxproj", "sln", "build", "compile", "link", "batch", "powershell")
    ReverseEngineering = @("pe", "coff", "disasm", "deobf", "parser", "scanner", "binary", "loader", "inject", "symbol", "reverse", "unpack")
}

# File extensions for each phase
$PhaseExtensions = @{
    Kernel = @(".asm", ".s", ".cpp", ".hpp", ".h", ".c", ".inc")
    GPU = @(".asm", ".cpp", ".hpp", ".h", ".glsl", ".hlsl", ".spv", ".comp", ".vert", ".frag")
    Loader = @(".cpp", ".hpp", ".h", ".c", ".py", ".rs")
    Build = @(".bat", ".ps1", ".cmake", ".txt", ".ninja", ".vcxproj", ".sln", ".props", ".targets")
    ReverseEngineering = @(".asm", ".cpp", ".hpp", ".h", ".c", ".py", ".rs", ".go")
}

function Get-FileScore {
    param($File, $Phase)
    $score = 0
    $reasons = @()
    
    # Check if referenced by active source (simplified - would need full dependency analysis)
    if ($File.Name -match "kernel|compute|gemm|matmul") {
        $score += $ScoreWeights.OptimizedAssembly
        $reasons += "OptimizedAssembly"
    }
    
    # Check for GPU code patterns
    if ($Phase -eq "GPU" -or $File.Content -match "vulkan|cuda|hip|shader") {
        $score += $ScoreWeights.GPUCode
        $reasons += "GPUCode"
    }
    
    # Check for tests
    if ($File.Name -match "test|spec|bench") {
        $score += $ScoreWeights.HasTests
        $reasons += "HasTests"
    }
    
    # Check for build files
    if ($File.Name -match "build|make|cmake|ninja|batch") {
        $score += $ScoreWeights.HasBuildFiles
        $reasons += "HasBuildFiles"
    }
    
    # Check modification time
    if ($File.LastWriteTime -gt (Get-Date).AddMonths(-3)) {
        $score += $ScoreWeights.RecentModification
        $reasons += "RecentModification"
    }
    
    # Check for empty scaffold
    if ($File.Length -lt 100) {
        $score += $ScoreWeights.EmptyScaffold
        $reasons += "EmptyScaffold"
    }
    
    return @{ Score = $score; Reasons = $reasons -join ";" }
}

function Find-OrphanCandidates {
    param($Phase)
    
    $keywords = $PhaseKeywords[$Phase]
    $extensions = $PhaseExtensions[$Phase]
    $candidates = @()
    
    Write-Host "Scanning for $Phase orphans..." -ForegroundColor Cyan
    
    # Search in common orphan locations
    $searchPaths = @(
        ".\archived_orphans",
        ".\worktrees",
        ".\history-*",
        ".\Full Source",
        ".\src\orphan",
        ".\orphan",
        ".\old",
        ".\backup",
        ".\archive"
    )
    
    foreach ($path in $searchPaths) {
        if (Test-Path $path) {
            Write-Host "  Searching: $path" -ForegroundColor Gray
            
            $files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue | 
                Where-Object { $extensions -contains $_.Extension.ToLower() }
            
            foreach ($file in $files) {
                # Quick content check for keywords
                $content = ""
                try {
                    if ($file.Length -lt 1MB) {
                        $content = Get-Content $file.FullName -Raw -ErrorAction SilentlyContinue
                    }
                } catch {}
                
                $hasKeyword = $false
                foreach ($kw in $keywords) {
                    if ($content -match $kw -or $file.Name -match $kw) {
                        $hasKeyword = $true
                        break
                    }
                }
                
                if ($hasKeyword -or $Phase -eq "All") {
                    $scoreResult = Get-FileScore -File $file -Phase $Phase
                    
                    # Calculate hash for duplicate detection
                    $hash = ""
                    try {
                        $hash = (Get-FileHash $file.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue).Hash.Substring(0, 16)
                    } catch {}
                    
                    $candidates += [PSCustomObject]@{
                        Path = $file.FullName
                        RelativePath = $file.FullName.Replace($PWD.Path, "").TrimStart("\")
                        Name = $file.Name
                        Extension = $file.Extension
                        Size = $file.Length
                        LastModified = $file.LastWriteTime
                        Phase = $Phase
                        Score = $scoreResult.Score
                        Reasons = $scoreResult.Reasons
                        Hash = $hash
                        KeywordsFound = ($keywords | Where-Object { $content -match $_ -or $file.Name -match $_ }) -join ";"
                    }
                }
            }
        }
    }
    
    return $candidates | Sort-Object Score -Descending
}

# Main execution
Write-Host "=== RawrXD Orphan Archaeology Tool ===" -ForegroundColor Green
Write-Host "Phase: $Phase | Output: $OutputFormat" -ForegroundColor Yellow
Write-Host ""

$candidates = Find-OrphanCandidates -Phase $Phase

Write-Host "Found $($candidates.Count) candidates" -ForegroundColor Green

# Generate output
$outputBase = Join-Path $OutputDir "$Phase`_candidates"

switch ($OutputFormat) {
    "CSV" {
        $csvPath = "$outputBase.csv"
        $candidates | Export-Csv -Path $csvPath -NoTypeInformation
        Write-Host "Exported to: $csvPath" -ForegroundColor Cyan
    }
    "JSON" {
        $jsonPath = "$outputBase.json"
        $candidates | ConvertTo-Json -Depth 3 | Out-File $jsonPath
        Write-Host "Exported to: $jsonPath" -ForegroundColor Cyan
    }
    "Markdown" {
        $mdPath = "$outputBase.md"
        $md = @("# $Phase Orphan Candidates`n")
        $md += "| Score | Path | Size | Reasons | Keywords |"
        $md += "|-------|------|------|---------|----------|"
        
        foreach ($c in $candidates | Select-Object -First 100) {
            $sizeKB = [math]::Round($c.Size / 1KB, 2)
            $md += "| $($c.Score) | ``$($c.RelativePath)`` | $($sizeKB)KB | $($c.Reasons) | $($c.KeywordsFound) |"
        }
        
        $md -join "`n" | Out-File $mdPath
        Write-Host "Exported to: $mdPath" -ForegroundColor Cyan
    }
}

# Generate summary
$resurrect = $candidates | Where-Object { $_.Score -ge 90 }
$merge = $candidates | Where-Object { $_.Score -ge 60 -and $_.Score -lt 90 }
$archive = $candidates | Where-Object { $_.Score -lt 60 }

Write-Host ""
Write-Host "=== Classification Summary ===" -ForegroundColor Green
Write-Host "RESURRECT (90-100): $($resurrect.Count) files" -ForegroundColor Magenta
Write-Host "MERGE (60-89): $($merge.Count) files" -ForegroundColor Yellow
Write-Host "ARCHIVE (<60): $($archive.Count) files" -ForegroundColor Gray

# Export summary
$summaryPath = Join-Path $OutputDir "$Phase`_summary.txt"
@"
RawrXD Orphan Archaeology - $Phase Phase
Generated: $(Get-Date)
Total Candidates: $($candidates.Count)

RESURRECT (90-100 points): $($resurrect.Count) files
$(($resurrect | Select-Object -First 10 | ForEach-Object { "  - $($_.RelativePath) [$($_.Score)]" }) -join "`n")

MERGE (60-89 points): $($merge.Count) files  
$(($merge | Select-Object -First 10 | ForEach-Object { "  - $($_.RelativePath) [$($_.Score)]" }) -join "`n")

ARCHIVE (<60 points): $($archive.Count) files
$(($archive | Select-Object -First 5 | ForEach-Object { "  - $($_.RelativePath) [$($_.Score)]" }) -join "`n")
"@ | Out-File $summaryPath

Write-Host "Summary: $summaryPath" -ForegroundColor Cyan
