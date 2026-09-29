#pragma once

// Compute build inclusion audit - Gates all compute build inclusion audit execution
// This authority audits compute build inclusion for completeness and correctness

namespace rawrxd::audit
{
    // Audit compute build inclusion
    void auditComputeBuildInclusion();
    
    // Write compute build inclusion audit receipt
    void writeComputeBuildInclusionAuditReceipt();
}
