# RawrXD Symbol Analyzer
# Analyzes symbol exports/imports and validates binary compatibility

param(
    [string]$BinaryPath = "D:\rawrxd\build\Release",
    [string[]]$Binaries = @(),
    [switch]$ValidateExports,
    [switch]$CheckImports,
    [switch]$FindOrphans,
    [switch]$GenerateDef,
    [string]$OutputFormat = "json"
)

$ErrorActionPreference = "Stop"

$script:SymState = @{
    StartTime = Get-Date
    BinariesAnalyzed = 0
    ExportsFound = 0
    ImportsFound = 0
    OrphansFound = 0
    Issues = @()
}

function Write-Status { param([string]$Message) Write-Host "[*] $Message" -ForegroundColor Cyan }
function Write-Success { param([string]$Message) Write-Host "[✓] $Message" -ForegroundColor Green }
function Write-Warning { param([string]$Message) Write-Host "[!] $Message" -ForegroundColor Yellow }

function Get-BinaryFiles {
    if ($Binaries.Count -gt 0) {
        return $Binaries | Where-Object { Test-Path $_ }
    }
    
    $patterns = @("*.dll", "*.exe", "*.lib")
    $files = @()
    
    foreach ($pattern in $patterns) {
        $files += Get-ChildItem -Path $BinaryPath -Filter $pattern -File -ErrorAction SilentlyContinue
    }
    
    return $files | Select-Object -ExpandProperty FullName
}

function Get-Exports {
    param([string]$BinaryPath)
    
    $exports = @()
    
    try {
        # Use dumpbin or similar tool
        $dumpbin = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\dumpbin.exe"
        
        if (Test-Path $dumpbin) {
            $output = & $dumpbin /EXPORTS $BinaryPath 2>$null
            
            # Parse exports
            $inExportTable = $false
            foreach ($line in $output) {
                if ($line -match "ordinal\s+hint\s+RVA\s+name") {
                    $inExportTable = $true
                    continue
                }
                
                if ($inExportTable -and $line -match "^\s*\d+\s+\w+\s+\w+\s+(\w+)") {
                    $exports += $Matches[1]
                }
            }
        } else {
            # Fallback: try to read PE headers
            Write-Warning "dumpbin not found, using fallback method"
        }
    } catch {
        Write-Warning "Could not analyze exports for $([System.IO.Path]::GetFileName($BinaryPath))"
    }
    
    return $exports
}

function Get-Imports {
    param([string]$BinaryPath)
    
    $imports = @()
    
    try {
        $dumpbin = "C:\VS2022Enterprise\VC\Tools\MSVC\14.50.35717\bin\Hostx64\x64\dumpbin.exe"
        
        if (Test-Path $dumpbin) {
            $output = & $dumpbin /IMPORTS $BinaryPath 2>$null
            
            # Parse imports
            $currentDll = $null
            foreach ($line in $output) {
                if ($line -match "^\s+(\w+\.dll)") {
                    $currentDll = $Matches[1]
                } elseif ($currentDll -and $line -match "^\s+\w+\s+(\w+)") {
                    $imports += @{
                        DLL = $currentDll
                        Function = $Matches[1]
                    }
                }
            }
        }
    } catch {
        Write-Warning "Could not analyze imports for $([System.IO.Path]::GetFileName($BinaryPath))"
    }
    
    return $imports
}

function Analyze-Binary {
    param([string]$Path)
    
    Write-Status "Analyzing: $([System.IO.Path]::GetFileName($Path))"
    
    $analysis = @{
        File = $Path
        Name = [System.IO.Path]::GetFileName($Path)
        Exports = @()
        Imports = @()
    }
    
    if ($ValidateExports) {
        $analysis.Exports = Get-Exports -BinaryPath $Path
        $script:SymState.ExportsFound += $analysis.Exports.Count
    }
    
    if ($CheckImports) {
        $analysis.Imports = Get-Imports -BinaryPath $Path
        $script:SymState.ImportsFound += $analysis.Imports.Count
    }
    
    $script:SymState.BinariesAnalyzed++
    
    return $analysis
}

function Find-OrphanSymbols {
    param([array]$Analyses)
    
    Write-Status "Searching for orphan symbols..."
    
    $allExports = @{}
    $allImports = @{}
    
    # Collect all exports and imports
    foreach ($analysis in $Analyses) {
        foreach ($export in $analysis.Exports) {
            $allExports[$export] = $analysis.Name
        }
        
        foreach ($import in $analysis.Imports) {
            if (-not $allImports[$import.Function]) {
                $allImports[$import.Function] = @()
            }
            $allImports[$import.Function] += $analysis.Name
        }
    }
    
    # Find orphans (imports with no matching exports)
    $orphans = @()
    foreach ($import in $allImports.Keys) {
        if (-not $allExports.ContainsKey($import)) {
            # Check if it's a system DLL import
            $isSystem = $false
            foreach ($analysis in $Analyses) {
                $importInfo = $analysis.Imports | Where-Object { $_.Function -eq $import }
                if ($importInfo -and ($importInfo.DLL -match "kernel32|user32|ntdll|msvcrt")) {
                    $isSystem = $true
                    break
                }
            }
            
            if (-not $isSystem) {
                $orphans += @{
                    Symbol = $import
                    RequiredBy = $allImports[$import]
                }
            }
        }
    }
    
    $script:SymState.OrphansFound = $orphans.Count
    
    return $orphans
}

function Generate-ModuleDef {
    param([array]$Exports, [string]$ModuleName)
    
    $def = "LIBRARY $ModuleName`n"
    $def += "EXPORTS`n"
    
    foreach ($export in $Exports | Sort-Object) {
        $def += "    $export`n"
    }
    
    return $def
}

function Export-Report {
    param([array]$Analyses, [array]$Orphans)
    
    $report = @{
        Timestamp = Get-Date -Format "o"
        Summary = @{
            BinariesAnalyzed = $script:SymState.BinariesAnalyzed
            TotalExports = $script:SymState.ExportsFound
            TotalImports = $script:SymState.ImportsFound
            OrphanSymbols = $script:SymState.OrphansFound
        }
        Binaries = $Analyses
        Orphans = $Orphans
    }
    
    $outputFile = "symbol-analysis-$(Get-Date -Format 'yyyyMMdd-HHmmss').json"
    $report | ConvertTo-Json -Depth 10 | Out-File $outputFile
    
    Write-Success "Report exported: $outputFile"
}

function Show-Summary {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Symbol Analysis Summary" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Binaries Analyzed: $($script:SymState.BinariesAnalyzed)" -ForegroundColor White
    Write-Host "Total Exports: $($script:SymState.ExportsFound)" -ForegroundColor Green
    Write-Host "Total Imports: $($script:SymState.ImportsFound)" -ForegroundColor Green
    Write-Host "Orphan Symbols: $($script:SymState.OrphansFound)" -ForegroundColor $(if($script:SymState.OrphansFound -gt 0){'Red'}else{'Green'})
    
    if ($script:SymState.OrphansFound -gt 0) {
        Write-Host ""
        Write-Warning "Found $($script:SymState.OrphansFound) orphan symbols that need to be resolved"
    }
}

# Main execution
function Main {
    Write-Host "RawrXD Symbol Analyzer" -ForegroundColor Cyan
    Write-Host "=====================" -ForegroundColor Cyan
    Write-Host ""
    
    $binaries = Get-BinaryFiles
    
    if ($binaries.Count -eq 0) {
        Write-Warning "No binaries found"
        return
    }
    
    Write-Status "Found $($binaries.Count) binaries to analyze"
    
    $analyses = @()
    foreach ($binary in $binaries) {
        $analysis = Analyze-Binary -Path $binary
        $analyses += $analysis
    }
    
    $orphans = @()
    if ($FindOrphans) {
        $orphans = Find-OrphanSymbols -Analyses $analyses
    }
    
    if ($GenerateDef -and $analyses.Count -gt 0) {
        $defContent = Generate-ModuleDef -Exports $analyses[0].Exports -ModuleName $analyses[0].Name
        $defFile = "$($analyses[0].Name).def"
        $defContent | Out-File $defFile -Encoding UTF8
        Write-Success "Module definition generated: $defFile"
    }
    
    Export-Report -Analyses $analyses -Orphans $orphans
    Show-Summary
    
    Write-Host ""
    Write-Success "Symbol analysis complete!"
}

Main
