#pragma once

// Compute dictionary audit - Gates all compute dictionary audit execution
// This authority audits compute dictionary for completeness and correctness

namespace rawrxd::audit
{
    // Audit compute dictionary
    void auditComputeDictionary();
    
    // Write compute dictionary audit receipt
    void writeComputeDictionaryAuditReceipt();
}
