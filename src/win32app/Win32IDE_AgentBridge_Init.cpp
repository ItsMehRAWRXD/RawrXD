// ============================================================================
// Win32IDE_AgentBridge_Init.cpp - AgentBridge Safe Initialization
// ============================================================================
// SEH-protected initialization that prevents IDE crashes on failure
// ============================================================================

#include "Win32IDE_AgentBridge_Init.hpp"
#include "Win32IDE.h"
#include "Win32IDE_LoRAKernelBridge.h"
#include "../include/RawrXD_FeatureRegistry.hpp"
#include "IDELogger.h"
#include <windows.h>
#include <sstream>

namespace RawrXD {
namespace AgentBridgeInit {

// Static state
static bool s_initialized = false;
static InitResult s_lastResult = InitResult::UnknownError;
static std::string s_lastError;
static int s_initAttempts = 0;

// Forward declaration for SEH-protected call
static bool CallInitializeAgenticBridge(Win32IDE* ide);

// ============================================================================
// Safe Initialization with SEH
// ============================================================================

bool InitializeSafe(Win32IDE* ide) {
    // Check if already initialized
    if (s_initialized) {
        s_lastResult = InitResult::AlreadyInitialized;
        return true;
    }
    
    // Check feature flag
    if (!FeatureRegistry::IsAgentBridgeEnabled()) {
        s_lastResult = InitResult::ConfigDisabled;
        s_lastError = "AgentBridge disabled by feature registry";
        LOG_INFO("AgentBridge: Disabled by feature registry");
        return false;
    }
    
    // Validate prerequisites
    std::string reason;
    if (!FeatureRegistry::CanEnableAgentBridge(reason)) {
        s_lastResult = InitResult::MissingConfig;
        s_lastError = reason.empty() ? "Prerequisites not met" : reason;
        LOG_WARNING("AgentBridge: Cannot initialize - " + s_lastError);
        return false;
    }
    
    s_initAttempts++;
    
    LOG_INFO("AgentBridge: Starting initialization (attempt " + 
             std::to_string(s_initAttempts) + ")");
    
    // Check if backend is ready
    if (!ide) {
        s_lastResult = InitResult::BackendNotReady;
        s_lastError = "IDE pointer is null";
        LOG_ERROR("AgentBridge: IDE pointer is null");
        return false;
    }
    
    // SEH-protected initialization (separate function to avoid unwinding issues)
    bool success = CallInitializeAgenticBridge(ide);
    
    if (success) {
        s_initialized = true;
        s_lastResult = InitResult::Success;
        s_lastError.clear();
        LOG_INFO("AgentBridge: Initialization successful");
        
        // Initialize LoRA Kernel Bridge
        if (LoRAKernel_Initialize()) {
            LOG_INFO("AgentBridge: LoRA Kernel Bridge initialized");
        } else {
            LOG_WARNING("AgentBridge: LoRA Kernel Bridge failed to initialize");
        }
    } else {
        s_initialized = false;
        s_lastResult = InitResult::ExceptionCaught;
        s_lastError = "SEH exception during initialization";
        LOG_ERROR("AgentBridge: Initialization failed with exception");
        OutputDebugStringA("[AgentBridge] Init failed - continuing without AI bridge\n");
    }
    
    return success;
}

// SEH-protected wrapper - no C++ objects that require unwinding
static bool CallInitializeAgenticBridge(Win32IDE* ide) {
    __try {
        ide->initializeAgenticBridge();
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// ============================================================================
// Status Getters
// ============================================================================

bool IsInitialized() {
    return s_initialized;
}

InitResult GetLastResult() {
    return s_lastResult;
}

const char* GetLastResultString() {
    switch (s_lastResult) {
        case InitResult::Success: return "Success";
        case InitResult::AlreadyInitialized: return "Already Initialized";
        case InitResult::ConfigDisabled: return "Disabled by Config";
        case InitResult::MissingConfig: return "Missing Configuration";
        case InitResult::BackendNotReady: return "Backend Not Ready";
        case InitResult::ExceptionCaught: return "Exception Caught";
        case InitResult::UnknownError: return "Unknown Error";
        default: return "Invalid Result";
    }
}

void Shutdown() {
    if (!s_initialized) {
        return;
    }
    
    // C-style logging (no C++ objects in __try block)
    OutputDebugStringA("[AgentBridge] Shutting down\n");
    
    // Shutdown LoRA Kernel Bridge
    LoRAKernel_Shutdown();
    OutputDebugStringA("[AgentBridge] LoRA Kernel Bridge shutdown\n");
    
    // SEH-protected shutdown
    __try {
        // TODO: Call actual shutdown if it exists
        // ide->shutdownAgenticBridge();
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        OutputDebugStringA("[AgentBridge] Exception during shutdown\n");
    }
    
    s_initialized = false;
    s_lastResult = InitResult::UnknownError;
}

bool RetryInitialization(Win32IDE* ide) {
    // Reset state and try again
    s_initialized = false;
    return InitializeSafe(ide);
}

InitStatus GetStatus() {
    InitStatus status;
    status.isInitialized = s_initialized;
    status.isEnabled = FeatureRegistry::IsAgentBridgeEnabled();
    status.lastError = s_lastError;
    status.initAttempts = s_initAttempts;
    status.canRetry = !s_initialized && status.isEnabled;
    return status;
}

} // namespace AgentBridgeInit
} // namespace RawrXD

// ============================================================================
// C API Implementation
// ============================================================================

extern "C" {

__declspec(dllexport) int RawrXD_AgentBridge_Initialize(void* ide) {
    return RawrXD::AgentBridgeInit::InitializeSafe(static_cast<Win32IDE*>(ide)) ? 1 : 0;
}

__declspec(dllexport) int RawrXD_AgentBridge_IsInitialized(void) {
    return RawrXD::AgentBridgeInit::IsInitialized() ? 1 : 0;
}

__declspec(dllexport) void RawrXD_AgentBridge_Shutdown(void) {
    RawrXD::AgentBridgeInit::Shutdown();
}

}
