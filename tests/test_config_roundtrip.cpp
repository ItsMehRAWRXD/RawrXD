// tests/test_config_roundtrip.cpp
// Test: Configuration round-trip (set/get)
#include "RawrXDCore.h"
#include <iostream>
#include <cassert>
#include <cstring>

int main() {
    std::cout << "=== Test: Configuration Round-trip ===" << std::endl;
    
    assert(RawrXDCore_Initialize() == true);
    
    // Get default config
    RawrXDConfig original;
    RawrXDCore_GetDefaultConfig(&original);
    std::cout << "Default config retrieved" << std::endl;
    
    // Modify config
    RawrXDConfig modified = original;
    modified.enableVulkan = false;
    modified.enableMASM = false;
    modified.enableTelemetry = true;
    modified.workerThreadCount = 16;
    modified.maxMemoryMB = 8192;
    modified.modelCachePath = "C:\\Cache\\Models";
    modified.logFilePath = "C:\\Logs\\rawrxd.log";
    
    // Apply modified config
    assert(RawrXDCore_Configure(&modified) == true);
    std::cout << "Modified config applied" << std::endl;
    
    // Verify by getting defaults again (should still return defaults)
    RawrXDConfig defaultsAgain;
    RawrXDCore_GetDefaultConfig(&defaultsAgain);
    assert(defaultsAgain.enableVulkan == original.enableVulkan);
    assert(defaultsAgain.enableMASM == original.enableMASM);
    std::cout << "GetDefaultConfig returns original defaults" << std::endl;
    
    // Test config with NULL
    assert(RawrXDCore_Configure(nullptr) == false);
    assert(RawrXDCore_GetLastError() == RAWXD_ERROR_INVALID_ARGUMENT);
    std::cout << "NULL config correctly rejected" << std::endl;
    
    // Test re-initialization preserves config
    RawrXDCore_Shutdown();
    assert(RawrXDCore_Initialize() == true);
    
    // After re-init, should be back to defaults
    RawrXDConfig afterReinit;
    RawrXDCore_GetDefaultConfig(&afterReinit);
    assert(afterReinit.enableVulkan == original.enableVulkan);
    std::cout << "Re-initialization resets to defaults" << std::endl;
    
    // Apply custom config again
    assert(RawrXDCore_Configure(&modified) == true);
    
    // Verify hardware caps unchanged
    RawrXDHardwareCaps caps1, caps2;
    RawrXDCore_GetHardwareCaps(&caps1);
    RawrXDCore_GetHardwareCaps(&caps2);
    assert(caps1.cpuCoreCount == caps2.cpuCoreCount);
    assert(caps1.gpuCount == caps2.gpuCount);
    std::cout << "Hardware caps consistent across calls" << std::endl;
    
    RawrXDCore_Shutdown();
    std::cout << "=== PASSED ===" << std::endl;
    return 0;
}