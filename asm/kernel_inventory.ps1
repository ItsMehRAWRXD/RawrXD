# ============================================================================
# Kernel Inventory Scanner for RawrXD/Sovereign
# ============================================================================
# Scans codebase for kernel implementations and generates inventory
# Usage: .\kernel_inventory.ps1 [-OutputFormat json|md|csv]
# ============================================================================

param(
    [string]$SearchPath = "d:\src",
    [string]$OutputFormat = "md",
    [string]$OutputFile = "KERNEL_INVENTORY.md"
)

# Kernel categories and their search patterns
$KernelPatterns = @{
    # MASM/Assembly kernels
    "MASM_GEMM"        = @("_gemm_", "gemm_", "GEMM_", "Sovereign.*GEMM")
    "MASM_Attention"   = @("_attention_", "Attention_", "Sovereign.*Attention", "attn_")
    "MASM_RMSNorm"     = @("rmsnorm", "RMSNorm", "_norm_", "layernorm")
    "MASM_Softmax"     = @("softmax", "Softmax", "_softmax_")
    "MASM_Dequant"     = @("dequant", "Dequant", "Sovereign.*Dequant")
    "MASM_AMX"         = @("_amx_", "AMX_", "Sovereign.*AMX")
    "MASM_FFN"         = @("_ffn_", "FFN_", "Sovereign.*FFN")
    "MASM_KVCache"     = @("kvcache", "KVCache", "kv_cache", "Sovereign.*KV")
    "MASM_Sampler"     = @("_sampler_", "Sampler_", "Sovereign.*Sampler")
    "MASM_Tokenizer"   = @("_tokenizer_", "Tokenizer_", "Sovereign.*Tokenizer")
    "MASM_DMA"         = @("_dma_", "DMA_", "Sovereign.*DMA")
    
    # C++ kernels
    "CPP_AVX2"         = @("AVX2", "avx2", "__m256")
    "CPP_AVX512"       = @("AVX512", "avx512", "__m512")
    "CPP_GEMM"         = @("class.*Gemm", "struct.*Gemm", "void.*[Gg]emm")
    "CPP_Attention"    = @("class.*Attention", "struct.*Attention", "void.*[Aa]ttention")
    "CPP_Transformer"  = @("class.*Transformer", "struct.*Transformer")
    
    # GPU kernels
    "GPU_Vulkan"       = @("vkCmd", "VkBuffer", "Vulkan", "SPIR-V")
    "GPU_HIP"          = @("hip", "HIP", "amd_comgr", "__global__")
    "GPU_CUDA"         = @("cuda", "CUDA", "__device__", "__global__")
}

# File extensions to scan
$FileExtensions = @("*.asm", "*.cpp", "*.h", "*.hpp", "*.c", "*.cu", "*.cl")

# Results storage
$Results = @{
    "MASM_Kernels" = @()
    "CPP_Kernels" = @()
    "GPU_Kernels" = @()
    "Untagged_Kernels" = @()
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "RawrXD Kernel Inventory Scanner" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Scanning: $SearchPath" -ForegroundColor Yellow
Write-Host ""

# Function to extract kernel info from a file
function Extract-KernelInfo {
    param($FilePath, $Content, $Pattern, $Category)
    
    $matches = [regex]::Matches($Content, $Pattern)
    foreach ($match in $matches) {
        $lineNum = ($Content.Substring(0, $match.Index).Split("`n")).Count
        $line = $Content.Split("`n")[$lineNum - 1].Trim()
        
        # Try to extract function/procedure name
        $name = "Unknown"
        if ($line -match "(PROC|proc|void|__global__)[\s\t]+(\w+)") {
            $name = $matches[2]
        } elseif ($line -match "(\w+)[\s\t]*(?:PROC|proc)") {
            $name = $matches[1]
        }
        
        [PSCustomObject]@{
            Name = $name
            File = $FilePath
            Line = $lineNum
            Category = $Category
            Code = $line
            Status = "Detected"
        }
    }
}

# Scan all files
$files = Get-ChildItem -Path $SearchPath -Recurse -Include $FileExtensions -ErrorAction SilentlyContinue
$totalFiles = $files.Count
$currentFile = 0

foreach ($file in $files) {
    $currentFile++
    if ($currentFile % 100 -eq 0) {
        Write-Progress -Activity "Scanning kernels" -Status "$currentFile of $totalFiles" -PercentComplete (($currentFile / $totalFiles) * 100)
    }
    
    try {
        $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }
        
        # Check for KERNEL_COMPLETE tags first
        $tagged = [regex]::Matches($content, "KERNEL_COMPLETE:\s*(.+?)[\r\n]")
        foreach ($tag in $tagged) {
            $lineNum = ($content.Substring(0, $tag.Index).Split("`n")).Count
            $kernelName = $tag.Groups[1].Value.Trim()
            
            $Results["MASM_Kernels"] += [PSCustomObject]@{
                Name = $kernelName
                File = $file.FullName
                Line = $lineNum
                Category = "Tagged"
                Code = $tag.Value.Trim()
                Status = "COMPLETE"
            }
        }
        
        # Scan for patterns based on file type
        if ($file.Extension -eq ".asm") {
            foreach ($category in $KernelPatterns.Keys) {
                if ($category.StartsWith("MASM")) {
                    foreach ($pattern in $KernelPatterns[$category]) {
                        $matches = [regex]::Matches($content, "^\s*(\w+)\s+PROC", [System.Text.RegularExpressions.RegexOptions]::Multiline)
                        foreach ($match in $matches) {
                            $procName = $match.Groups[1].Value
                            if ($procName -match $pattern -or $category -match $pattern) {
                                $lineNum = ($content.Substring(0, $match.Index).Split("`n")).Count
                                
                                # Check if already tagged
                                $alreadyTagged = $Results["MASM_Kernels"] | Where-Object { $_.Name -eq $procName -and $_.File -eq $file.FullName }
                                if (-not $alreadyTagged) {
                                    $Results["Untagged_Kernels"] += [PSCustomObject]@{
                                        Name = $procName
                                        File = $file.FullName
                                        Line = $lineNum
                                        Category = $category
                                        Code = $match.Value.Trim()
                                        Status = "NEEDS_TAG"
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        elseif ($file.Extension -in @(".cpp", ".h", ".hpp")) {
            # C++ kernel detection
            foreach ($category in $KernelPatterns.Keys) {
                if ($category.StartsWith("CPP")) {
                    foreach ($pattern in $KernelPatterns[$category]) {
                        $matches = [regex]::Matches($content, $pattern)
                        foreach ($match in $matches) {
                            $lineNum = ($content.Substring(0, $match.Index).Split("`n")).Count
                            $line = $content.Split("`n")[$lineNum - 1].Trim()
                            
                            $Results["CPP_Kernels"] += [PSCustomObject]@{
                                Name = $match.Value
                                File = $file.FullName
                                Line = $lineNum
                                Category = $category
                                Code = $line
                                Status = "Detected"
                            }
                        }
                    }
                }
            }
        }
    }
    catch {
        # Skip files that can't be read
    }
}

Write-Progress -Activity "Scanning kernels" -Completed

# Generate output based on format
switch ($OutputFormat) {
    "json" {
        $json = $Results | ConvertTo-Json -Depth 3
        $json | Out-File -FilePath $OutputFile
    }
    
    "csv" {
        $allKernels = @()
        $allKernels += $Results["MASM_Kernels"]
        $allKernels += $Results["CPP_Kernels"]
        $allKernels += $Results["GPU_Kernels"]
        $allKernels += $Results["Untagged_Kernels"]
        $allKernels | Export-Csv -Path $OutputFile -NoTypeInformation
    }
    
    default {  # Markdown
        $md = @"
# RawrXD Kernel Inventory

Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")

## Summary

| Category | Count | Status |
|----------|-------|--------|
| MASM Kernels (Tagged) | $($Results["MASM_Kernels"].Count) | COMPLETE |
| C++ Kernels | $($Results["CPP_Kernels"].Count) | Detected |
| GPU Kernels | $($Results["GPU_Kernels"].Count) | Detected |
| Untagged MASM | $($Results["Untagged_Kernels"].Count) | NEEDS_TAG |

---

## MASM Kernels (Tagged/COMPLETE)

"@
        
        # Group by category
        $grouped = $Results["MASM_Kernels"] | Group-Object Category
        foreach ($group in $grouped) {
            $md += "### $($group.Name)`n`n"
            $md += "| Kernel | File | Line |`n"
            $md += "|--------|------|------|`n"
            foreach ($kernel in $group.Group) {
                $shortFile = $kernel.File.Replace("$SearchPath\", "")
                $md += "| ``$($kernel.Name)`` | ``$shortFile`` | $($kernel.Line) |`n"
            }
            $md += "`n"
        }
        
        $md += @"
---

## Untagged Kernels (NEEDS_TAG)

These kernels need ``// KERNEL_COMPLETE: <name>`` tags added.

"@
        
        $md += "| Kernel | File | Line | Suggested Category |`n"
        $md += "|--------|------|------|-------------------|`n"
        foreach ($kernel in $Results["Untagged_Kernels"] | Select-Object -First 50) {
            $shortFile = $kernel.File.Replace("$SearchPath\", "")
            $md += "| ``$($kernel.Name)`` | ``$shortFile`` | $($kernel.Line) | $($kernel.Category) |`n"
        }
        
        $md += @"

---

## C++ Kernels

"@
        
        $cppGrouped = $Results["CPP_Kernels"] | Group-Object Category
        foreach ($group in $cppGrouped | Select-Object -First 10) {
            $md += "### $($group.Name) ($($group.Count) found)`n`n"
            foreach ($kernel in $group.Group | Select-Object -First 5) {
                $shortFile = $kernel.File.Replace("$SearchPath\", "")
                $md += "- ``$($kernel.Name)`` in ``$shortFile``:$($kernel.Line)`n"
            }
            $md += "`n"
        }
        
        $md += @"

---

## Tagging Convention

Add these tags to your kernel files:

**MASM:**
```asm
; KERNEL_COMPLETE: Sovereign_GEMM_F32_AVX512
Sovereign_GEMM_F32_AVX512 PROC
    ; ... implementation ...
Sovereign_GEMM_F32_AVX512 ENDP
```

**C++:**
```cpp
// KERNEL_COMPLETE: AVX2_RMSNorm_F32
void AVX2_RMSNorm_F32(...) {
    // ... implementation ...
}
```

---

*Generated by kernel_inventory.ps1*
"@
        
        $md | Out-File -FilePath $OutputFile
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "Scan Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "Results:" -ForegroundColor Yellow
Write-Host "  Tagged MASM Kernels:  $($Results["MASM_Kernels"].Count)" -ForegroundColor Green
Write-Host "  C++ Kernels:          $($Results["CPP_Kernels"].Count)" -ForegroundColor Cyan
Write-Host "  GPU Kernels:          $($Results["GPU_Kernels"].Count)" -ForegroundColor Cyan
Write-Host "  Untagged (needs work): $($Results["Untagged_Kernels"].Count)" -ForegroundColor Yellow
Write-Host ""
Write-Host "Output: $OutputFile" -ForegroundColor Magenta
