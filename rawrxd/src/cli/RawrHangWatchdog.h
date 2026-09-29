#pragma once

// Rawr hang watchdog authority - Gates rawr hang detection and monitoring
// This authority ensures every rawr command is monitored for hangs and timeout

namespace rawrxd::cli
{
    // Start hang watchdog
    void startHangWatchdog();
    
    // Record heartbeat
    void heartbeat();
    
    // Stop hang watchdog
    void stopHangWatchdog();
    
    // Write hang receipt
    void writeHangReceipt();
}
