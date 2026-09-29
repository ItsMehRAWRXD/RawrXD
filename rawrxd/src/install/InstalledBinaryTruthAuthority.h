#pragma once

// Installed binary truth authority - Gates installed binary validation and reconciliation
// This authority ensures every installed binary is explicitly validated and receipt-backed

namespace rawrxd::install
{
    // Verify installed rawr
    void verifyInstalledRawr();
    
    // Write installed binary receipt
    void writeInstalledBinaryReceipt();
}
