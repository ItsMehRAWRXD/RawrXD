#pragma once

// MoE compute authority - Gates all mixture of experts computation
// This authority ensures every MoE operation is explicitly timed and receipt-backed

namespace rawrxd::compute
{
    // Route experts
    void routeExperts(int expertCount, int expertsUsed, long long durationMs);
    
    // Compute expert
    void computeExpert(long long durationMs);
    
    // Combine experts
    void combineExperts(long long durationMs);
    
    // Write MoE receipt
    void writeMoeReceipt();
}
