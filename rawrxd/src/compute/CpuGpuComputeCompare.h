#pragma once

// CPU-GPU compute comparison authority - Gates CPU vs GPU compute comparison
// This authority ensures CPU vs GPU comparison is explicitly measured and receipt-backed

namespace rawrxd::compare
{
    // Run CPU-GPU compute comparison
    void runCpuGpuCompare();
    
    // Write compare receipt
    void writeCompareReceipt();
}
