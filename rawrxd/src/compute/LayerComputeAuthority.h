#pragma once

// Layer compute authority - Gates all layer execution including attention, FFN, MoE, and SSM
// This authority ensures every layer is explicitly timed and failure-tracked

namespace rawrxd::compute
{
    // Begin layer processing
    void beginLayer(int index);
    
    // Record attention computation
    void recordAttention(long long durationMs);
    
    // Record FFN computation
    void recordFFN(long long durationMs);
    
    // Record MoE computation
    void recordMoE(long long durationMs);
    
    // Record SSM computation
    void recordSSM(long long durationMs);
    
    // End layer processing
    void endLayer();
    
    // Write layer compute receipt
    void writeLayerComputeReceipt();
}
