#pragma once

// Compute trace audit - Gates all compute trace audit execution
// This authority audits compute trace policies for contamination and completeness

namespace rawrxd::audit
{
    // Audit compute trace policy
    void auditComputeTracePolicy();
    
    // Write compute trace audit receipt
    void writeComputeTraceAuditReceipt();
}
