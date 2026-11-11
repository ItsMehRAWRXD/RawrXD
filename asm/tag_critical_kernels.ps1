# ============================================================================
# Tag Critical Kernels Script
# ============================================================================
# Adds KERNEL_COMPLETE tags to existing Sovereign kernel files
# ============================================================================

param(
    [switch]$DryRun = $false,
    [switch]$Force = $false
)

$KernelTags = @{
    # Attention kernels
    "Sovereign_Attention_Output.obj" = "KERNEL_COMPLETE: Attention_Output_F32_AVX512"
    "Sovereign_Attention_Projections.obj" = "KERNEL_COMPLETE: Attention_QKV_Projections_F32"
    "Sovereign_Attention_Scoring.obj" = "KERNEL_COMPLETE: Attention_Scoring_F32"
    
    # GEMM kernels
    "Sovereign_Kernel_GEMM_AVX512.obj" = "KERNEL_COMPLETE: GEMM_F32_AVX512"
    "Sovereign_Kernel_Suite.obj" = "KERNEL_COMPLETE: GEMM_Suite_F32_AVX2"
    "Sovereign_Kernel.obj" = "KERNEL_COMPLETE: GEMM_Base_F32"
    
    # FFN
    "Sovereign_FFN.obj" = "KERNEL_COMPLETE: FFN_GateUpDown_F32"
    
    # Dequant
    "Sovereign_Dequant.obj" = "KERNEL_COMPLETE: Dequant_Q4K_Q8K_F32"
    "Sovereign_Dequant_Kernel_Simple.obj" = "KERNEL_COMPLETE: Dequant_Simple_F32"
    
    # KV Cache
    "Sovereign_KVCache_Planar.obj" = "KERNEL_COMPLETE: KVCache_Planar_F32"
    
    # AMX
    "Sovereign_AMX_INT8_Kernel.obj" = "KERNEL_COMPLETE: AMX_GEMM_INT8"
    
    # Sampler
    "Sovereign_Sampler.obj" = "KERNEL_COMPLETE: Sampler_TopK_TopP_F32"
    
    # Tokenizer
    "Sovereign_Tokenizer.obj" = "KERNEL_COMPLETE: Tokenizer_BPE_UTF8"
    
    # Infrastructure
    "Sovereign_Loader.obj" = "KERNEL_COMPLETE: Infra_GGUF_Loader"
    "Sovereign_Orchestrator.obj" = "KERNEL_COMPLETE: Infra_Graph_Orchestrator"
    "Sovereign_Exports.obj" = "KERNEL_COMPLETE: Infra_API_Exports"
    "Sovereign_GraphRunner.obj" = "KERNEL_COMPLETE: Infra_Graph_Runner"
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Sovereign Kernel Tagger" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$taggedCount = 0
$skippedCount = 0

foreach ($objFile in $KernelTags.Keys) {
    $tag = $KernelTags[$objFile]
    $baseName = $objFile -replace '\.obj$', ''
    
    # Look for source files
    $asmFile = "$baseName.asm"
    $cppFile = "$baseName.cpp"
    
    $sourceFile = $null
    if (Test-Path $asmFile) {
        $sourceFile = $asmFile
    } elseif (Test-Path $cppFile) {
        $sourceFile = $cppFile
    }
    
    if ($sourceFile) {
        $content = Get-Content $sourceFile -Raw
        
        # Check if already tagged
        if ($content -match "KERNEL_COMPLETE" -and -not $Force) {
            Write-Host "SKIPPED: $sourceFile (already tagged)" -ForegroundColor Yellow
            $skippedCount++
            continue
        }
        
        if ($DryRun) {
            Write-Host "WOULD TAG: $sourceFile" -ForegroundColor Green
            Write-Host "  Tag: $tag" -ForegroundColor Gray
        } else {
            # Add tag at the beginning
            $newContent = "; $tag`n;`n$content"
            Set-Content $sourceFile $newContent
            Write-Host "TAGGED: $sourceFile" -ForegroundColor Green
        }
        $taggedCount++
    } else {
        Write-Host "NOT FOUND: $baseName.{asm,cpp}" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "Tagged: $taggedCount" -ForegroundColor Green
Write-Host "Skipped: $skippedCount" -ForegroundColor Yellow
Write-Host ""

if ($DryRun) {
    Write-Host "This was a DRY RUN. Use -DryRun:`$false to apply tags." -ForegroundColor Magenta
}
