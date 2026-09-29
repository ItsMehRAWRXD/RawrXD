#pragma once

// Logits compute authority - Gates all logits computation including final norm and LM head
// This authority ensures every logits operation is explicitly measured and receipt-backed

namespace rawrxd::compute
{
    // Compute final norm
    void computeFinalNorm(long long durationMs);
    
    // Compute LM head
    void computeLmHead(long long durationMs);
    
    // Record logit stats
    void recordLogitStats(int vocabSize, bool finite, bool nan, bool inf, int argmax);
    
    // Write logits receipt
    void writeLogitsReceipt();
}
