#pragma once

// RMSNorm compute authority - Gates all root mean square normalization computation
// This authority ensures every RMSNorm operation is explicitly measured and receipt-backed

namespace rawrxd::compute
{
    // Apply RMSNorm
    void apply(int dim, double eps, bool inputFinite, bool outputFinite, 
               double min, double max, double mean, double l2);
    
    // Record stats
    void recordStats(double min, double max, double mean, double l2);
    
    // Write RMSNorm receipt
    void writeRmsReceipt();
}
