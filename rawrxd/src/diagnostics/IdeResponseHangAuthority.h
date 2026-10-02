#pragma once

// IDE response hang authority - Gates IDE response hang analysis via dumpbin
// This authority analyzes the IDE binary for potential hang causes

#include <string>

namespace rawrxd::diagnostics
{
    // Analyze IDE binary for hang causes
    void analyzeIdeForHang(const std::string& exePath);
    
    // Write IDE response hang analysis receipt
    void writeIdeResponseHangReceipt();
}
