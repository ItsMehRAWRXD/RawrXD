#pragma once

// Rawr run wildcard authority - Gates rawr run modelname "*" execution
// This authority ensures wildcard model execution is explicitly measured and receipt-backed

namespace rawrxd::cli
{
    // Expand wildcard model
    void expandWildcardModel();
    
    // Select wildcard model
    void selectWildcardModel();
    
    // Run wildcard prompt
    void runWildcardPrompt();
    
    // Write wildcard receipt
    void writeWildcardReceipt();
}
