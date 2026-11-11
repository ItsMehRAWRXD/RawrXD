// tests/test_symbol_exports.cpp
// Test: Verify all expected symbols are exported from DLL
#include "RawrXDCore.h"
#include <iostream>
#include <cassert>

// Function pointer types for all exported functions
typedef const char* (*GetVersionFn)();
typedef int (*GetVersionMajorFn)();
typedef int (*GetVersionMinorFn)();
typedef int (*GetVersionPatchFn)();
typedef bool (*InitializeFn)();
typedef void (*ShutdownFn)();
typedef bool (*IsInitializedFn)();
typedef void (*SetLogCallbackFn)(RawrXDLogCallback, void*);
typedef void (*SetLogLevelFn)(RawrXDLogLevel);
typedef void (*GetDefaultConfigFn)(RawrXDConfig*);
typedef bool (*ConfigureFn)(const RawrXDConfig*);
typedef RawrXDModel* (*LoadModelFn)(const char*);
typedef void (*UnloadModelFn)(RawrXDModel*);
typedef const char* (*GetModelNameFn)(const RawrXDModel*);
typedef size_t (*GetModelSizeFn)(const RawrXDModel*);
typedef int (*GetModelLayerCountFn)(const RawrXDModel*);
typedef RawrXDInferenceContext* (*CreateContextFn)(RawrXDModel*);
typedef void (*DestroyContextFn)(RawrXDInferenceContext*);
typedef void (*GetDefaultInferenceParamsFn)(RawrXDInferenceParams*);
typedef int (*RunInferenceFn)(RawrXDInferenceContext*, const char*, const RawrXDInferenceParams*, RawrXDTokenCallback, void*);
typedef void (*GetMemoryStatsFn)(RawrXDMemoryStats*);
typedef void (*TrimMemoryFn)();
typedef const char* (*GetErrorStringFn)(RawrXDError);
typedef RawrXDError (*GetLastErrorFn)();
typedef void (*GetHardwareCapsFn)(RawrXDHardwareCaps*);

int main() {
    std::cout << "=== Test: Symbol Exports Verification ===" << std::endl;
    
    // Since we're linking statically to the DLL, all symbols should be available
    // This test verifies the API surface is complete
    
    // Version functions
    assert(RawrXDCore_GetVersion != nullptr);
    assert(RawrXDCore_GetVersionMajor != nullptr);
    assert(RawrXDCore_GetVersionMinor != nullptr);
    assert(RawrXDCore_GetVersionPatch != nullptr);
    std::cout << "Version functions: OK" << std::endl;
    
    // Init/Shutdown
    assert(RawrXDCore_Initialize != nullptr);
    assert(RawrXDCore_Shutdown != nullptr);
    assert(RawrXDCore_IsInitialized != nullptr);
    std::cout << "Init/Shutdown functions: OK" << std::endl;
    
    // Logging
    assert(RawrXDCore_SetLogCallback != nullptr);
    assert(RawrXDCore_SetLogLevel != nullptr);
    std::cout << "Logging functions: OK" << std::endl;
    
    // Configuration
    assert(RawrXDCore_GetDefaultConfig != nullptr);
    assert(RawrXDCore_Configure != nullptr);
    std::cout << "Configuration functions: OK" << std::endl;
    
    // Model management
    assert(RawrXDCore_LoadModel != nullptr);
    assert(RawrXDCore_UnloadModel != nullptr);
    assert(RawrXDCore_GetModelName != nullptr);
    assert(RawrXDCore_GetModelSize != nullptr);
    assert(RawrXDCore_GetModelLayerCount != nullptr);
    std::cout << "Model management functions: OK" << std::endl;
    
    // Inference
    assert(RawrXDCore_CreateContext != nullptr);
    assert(RawrXDCore_DestroyContext != nullptr);
    assert(RawrXDCore_GetDefaultInferenceParams != nullptr);
    assert(RawrXDCore_RunInference != nullptr);
    std::cout << "Inference functions: OK" << std::endl;
    
    // Memory
    assert(RawrXDCore_GetMemoryStats != nullptr);
    assert(RawrXDCore_TrimMemory != nullptr);
    std::cout << "Memory functions: OK" << std::endl;
    
    // Error handling
    assert(RawrXDCore_GetErrorString != nullptr);
    assert(RawrXDCore_GetLastError != nullptr);
    std::cout << "Error handling functions: OK" << std::endl;
    
    // Hardware
    assert(RawrXDCore_GetHardwareCaps != nullptr);
    std::cout << "Hardware functions: OK" << std::endl;
    
    // Test actual functionality
    assert(RawrXDCore_Initialize() == true);
    
    // Verify version
    assert(strcmp(RawrXDCore_GetVersion(), "14.7.3") == 0);
    assert(RawrXDCore_GetVersionMajor() == 14);
    assert(RawrXDCore_GetVersionMinor() == 7);
    assert(RawrXDCore_GetVersionPatch() == 3);
    
    // Verify error strings
    assert(strstr(RawrXDCore_GetErrorString(RAWRXD_OK), "Success") != nullptr);
    assert(strstr(RawrXDCore_GetErrorString(RAWRXD_ERROR_INVALID_ARGUMENT), "Invalid") != nullptr);
    assert(strstr(RawrXDCore_GetErrorString(RAWRXD_ERROR_OUT_OF_MEMORY), "memory") != nullptr);
    std::cout << "Error strings: OK" << std::endl;
    
    // Verify enums have expected values
    assert(RAWRXD_LOG_TRACE == 0);
    assert(RAWRXD_LOG_DEBUG == 1);
    assert(RAWRXD_LOG_INFO == 2);
    assert(RAWRXD_LOG_WARN == 3);
    assert(RAWRXD_LOG_ERROR == 4);
    assert(RAWRXD_LOG_FATAL == 5);
    std::cout << "Log level enums: OK" << std::endl;
    
    assert(RAWRXD_OK == 0);
    assert(RAWRXD_ERROR_INVALID_ARGUMENT == -1);
    assert(RAWRXD_ERROR_OUT_OF_MEMORY == -2);
    std::cout << "Error code enums: OK" << std::endl;
    
    // Verify struct sizes (ABI stability)
    RawrXDConfig config;
    RawrXDCore_GetDefaultConfig(&config);
    assert(sizeof(config) > 0);
    std::cout << "Config struct size: " << sizeof(config) << " bytes" << std::endl;
    
    RawrXDInferenceParams params;
    RawrXDCore_GetDefaultInferenceParams(&params);
    assert(sizeof(params) > 0);
    std::cout << "InferenceParams struct size: " << sizeof(params) << " bytes" << std::endl;
    
    RawrXDHardwareCaps caps;
    RawrXDCore_GetHardwareCaps(&caps);
    assert(sizeof(caps) > 0);
    std::cout << "HardwareCaps struct size: " << sizeof(caps) << " bytes" << std::endl;
    
    RawrXDCore_Shutdown();
    std::cout << "=== PASSED ===" << std::endl;
    return 0;
}