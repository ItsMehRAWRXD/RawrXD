#pragma once

// IDE response completion authority - Gates all IDE response generation completion
// This authority ensures every IDE response is explicitly tracked and completion-validated

namespace rawrxd::ide
{
    // Begin IDE response processing
    void beginResponse();
    
    // Record stream completion
    void recordStreamDone();
    
    // Record callback completion
    void recordCallbackDone();
    
    // Record stdout flush completion
    void recordStdoutFlushDone();
    
    // Record stderr flush completion
    void recordStderrFlushDone();
    
    // Record UI render completion
    void recordUiDone();
    
    // Record worker thread join completion
    void recordThreadJoinDone();
    
    // Record process exit request
    void recordProcessExitRequested();
    
    // Record process exit completion
    void recordProcessExited();
    
    // Write IDE response completion receipt
    void writeResponseCompletionReceipt();
}
