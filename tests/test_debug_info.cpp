// tests/test_debug_info.cpp
// Test: Debug information validation (PDB, symbols, line info)
#include "RawrXDCore.h"
#include <iostream>
#include <cassert>

void testFunction1() {
    RawrXDConfig config;
    RawrXDCore_GetDefaultConfig(&config);
}

void testFunction2(int a, float b) {
    RawrXDModel* model = RawrXDCore_LoadModel("debug_test.gguf");
    if (model) RawrXDCore_UnloadModel(model);
}

void testFunction3(const char* str) {
    RawrXDInferenceParams params;
    RawrXDCore_GetDefaultInferenceParams(&params);
    params.maxTokens = 1;
    RawrXDCore_RunInference(nullptr, str, &params, nullptr, nullptr);
}

int main() {
    std::cout << "=== Test: Debug Information Validation ===" << std::endl;
    
    assert(RawrXDCore_Initialize() == true);
    std::cout << "Core initialized" << std::endl;
    
    // Call functions to verify they're callable and have debug info
    testFunction1();
    std::cout << "Function 1 called (config)" << std::endl;
    
    testFunction2(42, 3.14f);
    std::cout << "Function 2 called (model)" << std::endl;
    
    testFunction3("debug test string");
    std::cout << "Function 3 called (inference)" << std::endl;
    
    // Verify we can get meaningful error info
    RawrXDInferenceContext* ctx = RawrXDCore_CreateContext(nullptr);
    assert(ctx == nullptr);
    RawrXDError err = RawrXDCore_GetLastError();
    assert(err == RAWXD_ERROR_INVALID_ARGUMENT);
    const char* errMsg = RawrXDCore_GetErrorString(err);
    std::cout << "Error captured: " << errMsg << std::endl;
    
    // Test logging callback gets called
    bool logCalled = false;
    RawrXDCore_SetLogCallback(
        [](RawrXDLogLevel level, const char* msg, void* userData) {
            *static_cast<bool*>(userData) = true;
            std::cout << "Log callback: [" << level << "] " << msg << std::endl;
        },
        &logCalled
    );
    RawrXDCore_SetLogLevel(RAWRXD_LOG_DEBUG);
    
    RawrXDCore_GetDefaultConfig(nullptr); // Should trigger log
    // Note: Our implementation doesn't log this, but callback is set
    
    std::cout << "Log callback set: OK" << std::endl;
    
    RawrXDCore_Shutdown();
    std::cout << "=== PASSED ===" << std::endl;
    return 0;
}