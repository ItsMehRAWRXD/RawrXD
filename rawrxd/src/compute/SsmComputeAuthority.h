#pragma once

// SSM compute authority - Gates all state space model computation
// This authority ensures every SSM operation is explicitly timed and receipt-backed

namespace rawrxd::compute
{
    // Compute in
    void computeIn(int inner);
    
    // Update state
    void updateState(int stateSize, int heads, int groups, bool updated);
    
    // Compute out
    void computeOut(bool finiteOutput);
    
    // Write SSM receipt
    void writeSsmReceipt();
}
