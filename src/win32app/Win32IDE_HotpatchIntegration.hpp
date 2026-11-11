// ============================================================================
// RawrXD Win32IDE Hotpatch Integration - Phase 5
// ============================================================================
// Enables live model swapping in the IDE via Epoch-RCU hotpatch system
// ============================================================================

#pragma once

#include <string>
#include <atomic>
#include <thread>
#include <functional>

namespace RawrXD {

// Forward declaration
class Win32IDE;

// ============================================================================
// Hotpatch Integration for Win32IDE
// ============================================================================
class IDEHotpatchIntegration {
public:
    static IDEHotpatchIntegration& Instance();
    
    // Initialize with IDE instance
    void Initialize(Win32IDE* ide);
    void Shutdown();
    
    // Hotpatch operations
    bool RequestHotpatch(const std::string& modelPath);
    bool IsHotpatchInProgress() const;
    std::string GetActiveModelPath() const;
    std::string GetPendingModelPath() const;
    
    // Status
    struct Status {
        uint64_t epoch = 0;
        bool swapPending = false;
        std::string activeModel;
        std::string pendingModel;
        uint64_t inferencesCompleted = 0;
        uint64_t hotpatchesCompleted = 0;
    };
    Status GetStatus() const;
    
    // Callbacks for IDE
    using HotpatchCompleteCallback = std::function<void(const std::string& modelPath, bool success)>;
    void SetHotpatchCompleteCallback(HotpatchCompleteCallback cb);
    
    // Phase 6.6: Query active architecture from inference context
    std::string GetActiveArchitecture() const;
    
private:
    IDEHotpatchIntegration() = default;
    ~IDEHotpatchIntegration() = default;
    
    void MonitorThread();
    void NotifyHotpatchComplete(const std::string& path, bool success);
    
    Win32IDE* m_ide = nullptr;
    std::atomic<bool> m_running{false};
    std::atomic<bool> m_hotpatchInProgress{false};
    std::thread m_monitorThread;
    
    std::string m_activeModelPath;
    std::string m_pendingModelPath;
    
    HotpatchCompleteCallback m_completeCallback;
    
    mutable std::mutex m_mutex;
};

// ============================================================================
// C API for MASM bridge
// ============================================================================
extern "C" {
    // Called from MASM router when hotpatch completes
    void RawrXD_IDE_OnHotpatchComplete(const char* modelPath, int success);
    
    // Called from MASM router to get current IDE model
    const char* RawrXD_IDE_GetActiveModelPath();
}

} // namespace RawrXD
