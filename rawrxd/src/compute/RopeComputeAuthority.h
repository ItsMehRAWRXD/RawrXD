#pragma once

// RoPE compute authority - Gates all rotary position encoding computation
// This authority ensures every RoPE operation is explicitly configured and receipt-backed

namespace rawrxd::compute
{
    // Apply RoPE
    void apply(const std::string& style, double theta, int dim, int tokenPosition, bool finiteOutput);
    
    // Record theta
    void recordTheta(double theta);
    
    // Write RoPE receipt
    void writeRopeReceipt();
}
