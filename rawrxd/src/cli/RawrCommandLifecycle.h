#pragma once

// Rawr command lifecycle authority - Gates rawr command lifecycle tracking
// This authority ensures every rawr command is explicitly staged, timed, and failure-tracked

namespace rawrxd::cli
{
    // Begin command processing
    void beginCommand();
    
    // Record command stage
    void recordStage(const std::string& stage);
    
    // Record command exit
    void recordExit(int exitCode);
    
    // Write command lifecycle receipt
    void writeCommandLifecycleReceipt();
}
