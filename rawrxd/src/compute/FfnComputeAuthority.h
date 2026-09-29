#pragma once

// FFN compute authority - Gates all feed-forward network computation
// This authority ensures every FFN operation is explicitly timed and receipt-backed

namespace rawrxd::compute
{
    // Compute gate
    void computeGate(long long durationMs);
    
    // Compute up
    void computeUp(long long durationMs);
    
    // Compute activation
    void computeActivation(long long durationMs);
    
    // Compute down
    void computeDown(long long durationMs);
    
    // Write FFN receipt
    void writeFfnReceipt();
}
