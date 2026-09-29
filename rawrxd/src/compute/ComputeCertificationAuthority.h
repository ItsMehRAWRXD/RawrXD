#pragma once

// Compute certification authority - Gates all compute certification execution
// This authority ensures every compute certification is explicitly validated and receipt-backed

namespace rawrxd::compute_cert
{
    // Run all compute certifications
    void runAll();
    
    // Write compute certification receipt
    void writeCertificationReceipt();
}
