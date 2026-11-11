// tests/test_dll_load_unload.cpp
// Test: Basic DLL load/unload functionality
#include "RawrXDCore.h"
#include <iostream>
#include <cassert>

int main() {
    std::cout << "=== Test: DLL Load/Unload ===" << std::endl;
    
    // Test version functions (no init required)
    assert(RawrXDCore_GetVersionMajor() == 14);
    assert(RawrXDCore_GetVersionMinor() == 7);
    assert(RawrXDCore_GetVersionPatch() == 3);
    std::cout << "Version: " << RawrXDCore_GetVersion() << std::endl;
    
    // Test initialization
    assert(RawrXDCore_Initialize() == true);
    assert(RawrXDCore_IsInitialized() == true);
    std::cout << "Initialized successfully" << std::endl;
    
    // Test double initialization fails
    assert(RawrXDCore_Initialize() == false);
    assert(RawrXDCore_GetLastError() == RAWXD_ERROR_ALREADY_INITIALIZED);
    std::cout << "Double init correctly rejected" << std::endl;
    
    // Test shutdown
    RawrXDCore_Shutdown();
    assert(RawrXDCore_IsInitialized() == false);
    std::cout << "Shutdown successful" << std::endl;
    
    // Test re-initialization after shutdown
    assert(RawrXDCore_Initialize() == true);
    std::cout << "Re-initialization successful" << std::endl;
    
    RawrXDCore_Shutdown();
    std::cout << "Final shutdown successful" << std::endl;
    
    std::cout << "=== PASSED ===" << std::endl;
    return 0;
}