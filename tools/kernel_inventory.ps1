# =============================================================================
# RawrXD Kernel Inventory Scanner
# Scans codebase for KERNEL_COMPLETE tags and generates inventory
# =============================================================================

param(
    [string]$RootPath = "d:\rawrxd",
    [string]$OutputFile = "KERNEL_INVENTORY.md",
    [switch]$ScanAll,
    [switch]$GenerateTags
)

# Color output
function Write-ColorOutput($ForegroundColor) {
    $fc = $host.UI.RawUI.ForegroundColor
    $host.UI.RawUI.ForegroundColor = $ForegroundColor
    if ($args) { Write-Output $args }
    $host.UI.RawUI.ForegroundColor = $fc
}

Write-ColorOutput Green "========================================"
Write-ColorOutput Green "RawrXD Kernel Inventory Scanner"
Write-ColorOutput Green "========================================"
Write-Output ""

# File patterns to scan
$patterns = @{
    'MASM' = '*.asm'
    'C++' = '*.cpp', '*.hpp', '*.h'
    'Vulkan' = '*.spv', '*.comp', '*.glsl'
}

# Kernel categories to detect
$kernelPatterns = @(
    'Gemm|GEMM|gemm',
    'Attention|ATTENTION|attention',
    'RMSNorm|RMSNORM|rms_norm',
    'Softmax|SOFTMAX|softmax',
    'DMA|dma|SDMA|sdma',
    'NF4|nf4|Q4_0|Q8_0|Quant|quant',
    'Medusa|MEDUSA|medusa',
    'Transformer|TRANSFORMER|transformer',
    'Flash|FLASH|flash',
    'KV|kv_cache|KeyValue',
    'SiLU|silu|SwiGLU|swiglu',
    'RoPE|rope|Rotary',
    'MatMul|matmul',
    'Dequant|dequant',
    'Inference|inference'
)

# Results storage
$completedKernels = @()
$potentialKernels = @()
$stats = @{
    'MASM' = 0
    'C++' = 0
    'Vulkan' = 0
    'TotalFiles' = 0
}

# Scan for KERNEL_COMPLETE tags
function Scan-CompletedKernels {
    Write-ColorOutput Yellow "Scanning for KERNEL_COMPLETE tags..."
    
    foreach ($type in $patterns.Keys) {
        $exts = $patterns[$type]
        foreach ($ext in $exts) {
            $files = Get-ChildItem -Path $RootPath -Recurse -Filter $ext -ErrorAction SilentlyContinue | 
                     Where-Object { -not $_.FullName.Contains("history\all_versions") }
            foreach ($file in $files) {
                $stats['TotalFiles']++
                
                # Check for KERNEL_COMPLETE tag
                try {
                    $matches = Select-String -Path $file.FullName -Pattern "KERNEL_COMPLETE:\s*(\S+)" -AllMatches -ErrorAction SilentlyContinue
                    if ($matches) {
                        foreach ($match in $matches) {
                            $kernelName = $match.Matches[0].Groups[1].Value
                            $completedKernels += [PSCustomObject]@{
                                Name = $kernelName
                                File = $file.FullName.Replace($RootPath, "").TrimStart("\", "/")
                                Line = $match.LineNumber
                                Type = $type
                                Language = if ($type -eq 'MASM') { 'MASM64' } else { 'C++17' }
                                Status = 'COMPLETE'
                            }
                            $stats[$type]++
                        }
                    }
                } catch {
                    # Skip files that can't be read
                }
            }
        }
    }
    
    Write-ColorOutput Green "Found $($completedKernels.Count) completed kernels"
}

# Scan for potential kernels (if -ScanAll)
function Scan-PotentialKernels {
    if (-not $ScanAll) { return }
    
    Write-ColorOutput Yellow "`nScanning for potential kernels..."
    
    foreach ($pattern in $kernelPatterns) {
        $files = Get-ChildItem -Path $RootPath -Recurse -Include *.cpp, *.hpp, *.h, *.asm -ErrorAction SilentlyContinue | 
                 Where-Object { -not $_.FullName.Contains("history\all_versions") } |
                 Select-String -Pattern $pattern -List -ErrorAction SilentlyContinue |
                 Select-Object -Unique Path
        
        foreach ($file in $files) {
            # Skip if already tagged
            $alreadyTagged = $completedKernels | Where-Object { $_.File -eq $file.Path.Replace($RootPath, "").TrimStart("\", "/") }
            if (-not $alreadyTagged) {
                $potentialKernels += [PSCustomObject]@{
                    File = $file.Path.Replace($RootPath, "").TrimStart("\", "/")
                    Pattern = $pattern
                    Status = 'POTENTIAL'
                }
            }
        }
    }
    
    Write-ColorOutput Green "Found $($potentialKernels.Count) potential kernels"
}

# Generate markdown inventory
function Generate-Inventory {
    Write-ColorOutput Yellow "`nGenerating inventory..."
    
    $md = @"
# RawrXD Kernel Inventory

**Generated:** $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")  
**Root Path:** $RootPath

## Summary

| Category | Count |
|----------|-------|
| Completed Kernels | $($completedKernels.Count) |
| MASM Kernels | $($stats['MASM']) |
| C++ Kernels | $($stats['C++']) |
| Vulkan Kernels | $($stats['Vulkan']) |
| Total Files Scanned | $($stats['TotalFiles']) |

"@

    if ($completedKernels.Count -gt 0) {
        $md += @"

## Completed Kernels

| Kernel Name | File | Line | Type | Language |
|-------------|------|------|------|----------|
"@
        
        foreach ($kernel in ($completedKernels | Sort-Object Type, Name)) {
            $md += "| ``$($kernel.Name)`` | ``$($kernel.File)`` | $($kernel.Line) | $($kernel.Type) | $($kernel.Language) |`n"
        }
    }
    
    # Group by type
    $md += @"

## By Category

"@
    
    $grouped = $completedKernels | Group-Object Type
    foreach ($group in $grouped) {
        $md += "### $($group.Name) Kernels ($($group.Count))\n\n"
        foreach ($kernel in ($group.Group | Sort-Object Name)) {
            $md += "- **$($kernel.Name)** - ``$($kernel.File):$($kernel.Line)``\n"
        }
        $md += "\n"
    }
    
    if ($potentialKernels.Count -gt 0 -and $ScanAll) {
        $md += @"
## Potential Kernels (Untagged)

| File | Detected Pattern |
|------|------------------|
"@
        foreach ($k in $potentialKernels) {
            $md += "| ``$($k.File)`` | $($k.Pattern) |\n"
        }
    }
    
    $md += @"

## Tagging Convention

To mark a kernel as complete, add this comment:

**C++:**
```cpp
// KERNEL_COMPLETE: Kernel_Name_Here
void Kernel_Name_Here(...) { }
```

**MASM:**
```asm
; KERNEL_COMPLETE: Kernel_Name_Here
Kernel_Name_Here PROC
    ...
Kernel_Name_Here ENDP
```

## Quick Reference

```powershell
# Scan for completed kernels
.\tools\kernel_inventory.ps1

# Scan all files for potential kernels
.\tools\kernel_inventory.ps1 -ScanAll

# Generate with custom output
.\tools\kernel_inventory.ps1 -OutputFile "docs/KERNELS.md"
```

---
*This inventory is auto-generated. Do not edit manually.*
"@
    
    $md | Out-File -FilePath (Join-Path $RootPath $OutputFile) -Encoding UTF8
    Write-ColorOutput Green "`nInventory saved to: $OutputFile"
}

# Generate tag snippets for untagged files
function Generate-Tags {
    if (-not $GenerateTags) { return }
    
    Write-ColorOutput Yellow "`nGenerating tag snippets..."
    
    $tagFile = Join-Path $RootPath "tools\kernel_tags_snippets.txt"
    $snippets = "# Kernel Tag Snippets - Add these to your files`n"
    $snippets += "# Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")`n`n"
    
    # Find files with kernel-like names but no tags
    $candidateFiles = Get-ChildItem -Path $RootPath -Recurse -Include *.cpp, *.hpp, *.asm | 
                      Where-Object { $_.Name -match "kernel|gemm|attention|rmsnorm|softmax|dma|nf4|transformer" }
    
    foreach ($file in $candidateFiles) {
        $relPath = $file.FullName.Replace($RootPath, "").TrimStart("\", "/")
        $alreadyTagged = $completedKernels | Where-Object { $_.File -eq $relPath }
        
        if (-not $alreadyTagged) {
            $baseName = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
            $kernelName = $baseName -replace "[_-]", "_" -replace "[^a-zA-Z0-9_]", ""
            
            if ($file.Extension -eq ".asm") {
                $snippets += "# File: $relPath`n"
                $snippets += "; KERNEL_COMPLETE: $kernelName`n"
                $snippets += "$kernelName PROC`n"
                $snippets += "    ; TODO: Add implementation`n"
                $snippets += "$kernelName ENDP`n`n"
            } else {
                $snippets += "// File: $relPath`n"
                $snippets += "// KERNEL_COMPLETE: $kernelName`n"
                $snippets += "void $kernelName(...) {`n"
                $snippets += "    // TODO: Add implementation`n"
                $snippets += "}`n`n"
            }
        }
    }
    
    $snippets | Out-File -FilePath $tagFile -Encoding UTF8
    Write-ColorOutput Green "Tag snippets saved to: tools\kernel_tags_snippets.txt"
}

# Main execution
Scan-CompletedKernels
Scan-PotentialKernels
Generate-Inventory
Generate-Tags

Write-Output ""
Write-ColorOutput Green "========================================"
Write-ColorOutput Green "Scan Complete!"
Write-ColorOutput Green "========================================"
Write-Output ""
Write-Output "Completed Kernels: $($completedKernels.Count)"
Write-Output "MASM: $($stats['MASM']) | C++: $($stats['C++']) | Vulkan: $($stats['Vulkan'])"
Write-Output ""
Write-Output "View inventory: $(Join-Path $RootPath $OutputFile)"
