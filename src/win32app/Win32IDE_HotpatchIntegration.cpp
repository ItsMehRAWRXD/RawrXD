// ============================================================================
// RawrXD Win32IDE Hotpatch Integration - Phase 5 Implementation
// ============================================================================

#include "Win32IDE_HotpatchIntegration.hpp"
#include "Win32IDE.h"
#include "../cli/gguf_validator.hpp"
#include <cstdio>
#include <chrono>

namespace RawrXD {

// External router functions from MASM
extern "C" {
    uint64_t RawrXD_RequestHotpatch(void* modelDescriptor, uint64_t gpuFence);
    uint64_t RawrXD_CheckEpochSwap();
    uint64_t RawrXD_GetEpochCounter();
    uint64_t RawrXD_IsSwapPending();
    uint64_t RawrXD_GetActiveEpochSlot();
}

// ============================================================================
// IDEHotpatchIntegration Implementation
// ============================================================================

IDEHotpatchIntegration& IDEHotpatchIntegration::Instance() {
    static IDEHotpatchIntegration instance;
    return instance;
}

void IDEHotpatchIntegration::Initialize(Win32IDE* ide) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_ide = ide;
    m_running = true;
    
    printf("[IDEHotpatchIntegration] Initialized\n");
    
    // Start monitor thread
    m_monitorThread = std::thread(&IDEHotpatchIntegration::MonitorThread, this);
}

void IDEHotpatchIntegration::Shutdown() {
    m_running = false;
    if (m_monitorThread.joinable()) {
        m_monitorThread.join();
    }
    printf("[IDEHotpatchIntegration] Shutdown complete\n");
}

bool IDEHotpatchIntegration::RequestHotpatch(const std::string& modelPath) {
    if (modelPath.empty()) {
        printf("[IDEHotpatchIntegration] ERROR: Empty model path\n");
        return false;
    }
    
    if (m_hotpatchInProgress.load()) {
        printf("[IDEHotpatchIntegration] WARNING: Hotpatch already in progress\n");
        return false;
    }
    
    // Phase 6.5: Pre-flight validation gate
    printf("[IDEHotpatchIntegration] Validating GGUF: %s\n", modelPath.c_str());
    auto validation = GGUFValidator::QuickValidate(modelPath);
    
    if (!validation.has_value()) {
        std::string errorMsg = "[IDEHotpatchIntegration] ERROR: GGUF validation failed: " + 
                               std::string(GGUFValidator::ErrorToString(validation.error()));
        printf("%s\n", errorMsg.c_str());
        
        // Surface error to user via IDE window
        if (m_ide) {
            std::string alertText = "Failed to validate GGUF model.\n\nError: " + 
                                   std::string(GGUFValidator::ErrorToString(validation.error()));
            ::MessageBoxA(m_ide->getMainWindow(), alertText.c_str(), 
                         "RawrXD Hotpatch Error", MB_OK | MB_ICONERROR);
        }
        
        // TODO: Wire to telemetry pipeline
        // Telemetry::LogEvent("HOTPATCH_VALIDATION_FAILED", {{"path", modelPath}, {"error", GGUFValidator::ErrorToString(validation.error())}});
        
        return false;
    }
    
    printf("[IDEHotpatchIntegration] GGUF validation passed\n");
    // TODO: Wire to telemetry pipeline
    // Telemetry::LogEvent("HOTPATCH_VALIDATION_PASSED", {{"path", modelPath}});
    
    // Phase 6.6: Architecture compatibility gate
    std::string incomingArch = GGUFValidator::ExtractArchitecture(modelPath);
    std::string activeArch = GetActiveArchitecture(); // Query from inference context
    
    if (!incomingArch.empty() && !activeArch.empty() && incomingArch != activeArch) {
        std::string errorMsg = "[IDEHotpatchIntegration] ERROR: Architecture mismatch! " +
                              incomingArch + " vs " + activeArch;
        printf("%s\n", errorMsg.c_str());
        
        if (m_ide) {
            std::string alertText = "Architecture Mismatch!\n\n" +
                                   "Active execution kernel: " + activeArch + "\n" +
                                   "Selected model weights:  " + incomingArch + "\n\n" +
                                   "Hotpatch aborted to prevent memory corruption.";
            ::MessageBoxA(m_ide->getMainWindow(), alertText.c_str(),
                         "RawrXD Security Gate Failure", MB_OK | MB_ICONERROR);
        }
        
        // TODO: Wire to telemetry pipeline
        // Telemetry::LogEvent("HOTPATCH_ARCH_MISMATCH", {{"path", modelPath}, {"incoming", incomingArch}, {"active", activeArch}});
        
        return false;
    }
    
    if (!incomingArch.empty()) {
        printf("[IDEHotpatchIntegration] Architecture compatibility verified: %s\n", incomingArch.c_str());
    }
    
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_pendingModelPath = modelPath;
        m_hotpatchInProgress = true;
    }
    
    printf("[IDEHotpatchIntegration] Requesting hotpatch: %s\n", modelPath.c_str());
    
    // Create model descriptor (in production, this would be a real ModelDescriptor*)
    // For now, we use the path as a token
    static std::string storedPath = modelPath;
    uint64_t result = RawrXD_RequestHotpatch((void*)storedPath.c_str(), 0);
    
    if (result == 0) {
        printf("[IDEHotpatchIntegration] Hotpatch request accepted (epoch will increment)\n");
        return true;
    } else if (result == 1) {
        printf("[IDEHotpatchIntegration] Hotpatch deferred: already pending\n");
        m_hotpatchInProgress = false;
        return false;
    } else if (result == 2) {
        printf("[IDEHotpatchIntegration] Hotpatch deferred: inference active\n");
        // Still in progress - will complete when inference finishes
        return true;
    } else {
        printf("[IDEHotpatchIntegration] ERROR: Hotpatch request failed with code %llu\n", result);
        m_hotpatchInProgress = false;
        return false;
    }
}

bool IDEHotpatchIntegration::IsHotpatchInProgress() const {
    return m_hotpatchInProgress.load();
}

std::string IDEHotpatchIntegration::GetActiveModelPath() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_activeModelPath;
}

std::string IDEHotpatchIntegration::GetPendingModelPath() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_pendingModelPath;
}

// Phase 6.6: Query active architecture from inference context
// TODO: Replace with actual query to inference engine when available
// For now, returns "llama" as the active test_llama_decode configuration
std::string IDEHotpatchIntegration::GetActiveArchitecture() const {
    // Query the active inference context
    // In production, this should call into the inference engine:
    // return InferenceEngine::GetActiveArchitecture();
    
    // Current implementation: hardcoded for test_llama_decode target
    // This will be replaced when multi-architecture support is added
    return "llama";
}

IDEHotpatchIntegration::Status IDEHotpatchIntegration::GetStatus() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    Status status;
    status.epoch = RawrXD_GetEpochCounter();
    status.swapPending = RawrXD_IsSwapPending() != 0;
    status.activeModel = m_activeModelPath;
    status.pendingModel = m_pendingModelPath;
    return status;
}

void IDEHotpatchIntegration::SetHotpatchCompleteCallback(HotpatchCompleteCallback cb) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_completeCallback = cb;
}

void IDEHotpatchIntegration::MonitorThread() {
    printf("[IDEHotpatchIntegration] Monitor thread started\n");
    
    while (m_running.load()) {
        // Check for swap completion
        if (m_hotpatchInProgress.load()) {
            RawrXD_CheckEpochSwap();
            
            // Check if swap is no longer pending
            if (RawrXD_IsSwapPending() == 0) {
                // Swap completed
                std::string completedPath;
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    completedPath = m_pendingModelPath;
                    m_activeModelPath = completedPath;
                    m_pendingModelPath.clear();
                    m_hotpatchInProgress = false;
                }
                
                printf("[IDEHotpatchIntegration] Hotpatch completed: %s\n", completedPath.c_str());
                NotifyHotpatchComplete(completedPath, true);
            }
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    printf("[IDEHotpatchIntegration] Monitor thread exiting\n");
}

void IDEHotpatchIntegration::NotifyHotpatchComplete(const std::string& path, bool success) {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_completeCallback) {
        m_completeCallback(path, success);
    }
    
    // Also notify IDE via window message if available
    if (m_ide && m_ide->m_hwnd) {
        // Post message to IDE window for UI updates
        // WM_USER + 0x700 = Hotpatch complete
        PostMessage(m_ide->m_hwnd, WM_USER + 0x700, success ? 1 : 0, (LPARAM)path.c_str());
    }
}

} // namespace RawrXD

// ============================================================================
// C API Implementation
// ============================================================================

extern "C" {

void RawrXD_IDE_OnHotpatchComplete(const char* modelPath, int success) {
    printf("[C API] Hotpatch complete: %s (success=%d)\n", modelPath ? modelPath : "null", success);
    
    if (modelPath) {
        RawrXD::IDEHotpatchIntegration::Instance().NotifyHotpatchComplete(modelPath, success != 0);
    }
}

const char* RawrXD_IDE_GetActiveModelPath() {
    static std::string path;
    path = RawrXD::IDEHotpatchIntegration::Instance().GetActiveModelPath();
    return path.c_str();
}

} // extern "C"

#pragma comment(linker, "/EXPORT:RawrXD_IDE_OnHotpatchComplete")
#pragma comment(linker, "/EXPORT:RawrXD_IDE_GetActiveModelPath")
