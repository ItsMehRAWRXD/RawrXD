#==============================================================================
# diagnose_kernels.ps1
# Diagnostic script for Titan kernel integration issues
#==============================================================================

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "Titan Kernel Integration Diagnostics" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""

# Check if test executable exists
$testExe = "d:\rawrxd\test_titan_dispatch.exe"
if (Test-Path $testExe) {
    Write-Host "✓ test_titan_dispatch.exe found" -ForegroundColor Green
    
    # Get file info
    $fileInfo = Get-Item $testExe
    Write-Host "  Size: $($fileInfo.Length) bytes"
    Write-Host "  Modified: $($fileInfo.LastWriteTime)"
} else {
    Write-Host "✗ test_titan_dispatch.exe NOT found" -ForegroundColor Red
}

Write-Host ""
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "Analysis of Test Results" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "ISSUE IDENTIFIED: Kernel execution produces garbage output" -ForegroundColor Yellow
Write-Host ""
Write-Host "Evidence:"
Write-Host "  - Execution time: 33μs (suspiciously fast)"
Write-Host "  - CPU reference:  175,381μs (expected)"
Write-Host "  - Error rate:     99.95% (262,015/262,144 values wrong)"
Write-Host "  - Max error:      3.4e+38 (essentially infinity)"
Write-Host ""

Write-Host "ROOT CAUSE HYPOTHESIS:" -ForegroundColor Yellow
Write-Host ""
Write-Host "1. NULL Function Pointer" -ForegroundColor White
Write-Host "   The kernel function pointer is null, but the code doesn't check"
Write-Host "   for null before calling, leading to undefined behavior."
Write-Host ""
Write-Host "2. Struct Layout Mismatch" -ForegroundColor White
Write-Host "   The GPU_KERNEL_DESCRIPTOR struct in C++ doesn't match what"
Write-Host "   the MASM code expects, causing parameter misalignment."
Write-Host ""
Write-Host "3. Calling Convention Mismatch" -ForegroundColor White
Write-Host "   Parameters not passed correctly to the kernel functions."
Write-Host ""

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "Recommended Fixes" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "IMMEDIATE ACTIONS:" -ForegroundColor Green
Write-Host ""
Write-Host "1. Add null pointer checks in Execute_Q4Q8_MatMul:"
Write-Host "   if (!g_kernelTable.q4q8_matmul_intrinsics && "
Write-Host "       !g_kernelTable.q4_0_q8_0_matmul) {"
Write-Host "       return ERROR_PROC_NOT_FOUND;"
Write-Host "   }"
Write-Host ""
Write-Host "2. Add debug logging to print function pointer values"
Write-Host "   at initialization time."
Write-Host ""
Write-Host "3. Verify struct layout matches between C++ and MASM:"
Write-Host "   - Check sizeof(GPU_KERNEL_DESCRIPTOR)"
Write-Host "   - Check field offsets"
Write-Host "   - Ensure #pragma pack is consistent"
Write-Host ""
Write-Host "4. Test kernels directly (bypass Titan dispatch):"
Write-Host "   Call Sovereign_InitKernelTable() and invoke"
Write-Host "   kernels directly to verify they work."
Write-Host ""

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host "Next Steps" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Option A: Rebuild test with debug logging"
Write-Host "Option B: Create minimal direct kernel test"
Write-Host "Option C: Check library exports with dumpbin"
Write-Host "Option D: Verify struct layout with diagnostics"
Write-Host ""
