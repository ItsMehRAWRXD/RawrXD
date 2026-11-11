#pragma once
#include <windows.h>
#include <cstdint>
#include <functional>
#include <atomic>
#include <vector>
#include <mutex>

// =============================================================================
// VEH_Watchdog - Vectored Exception Handler for Self-Modification Safety
// Catches crashes during patch execution and triggers automatic rollback
// =============================================================================

namespace RawrXD {
namespace Sovereign {

// =============================================================================
// Exception Context - Extended CPU state at crash point
// =============================================================================

struct ExceptionContext {
    EXCEPTION_RECORD exceptionRecord;
    CONTEXT contextRecord;
    
    // Additional metadata
    uint64_t timestamp;
    uint64_t patch_epoch;      // Which patch was active
    uintptr_t faulting_address;
    
    ExceptionContext() 
        : timestamp(0)
        , patch_epoch(0)
        , faulting_address(0) 
    {
        ZeroMemory(&exceptionRecord, sizeof(exceptionRecord));
        ZeroMemory(&contextRecord, sizeof(contextRecord));
    }
};

// =============================================================================
// Watchdog Action - Response to exception
// =============================================================================

enum class WatchdogAction {
    ROLLBACK_AND_CONTINUE,   // Restore pre-patch state, resume execution
    TERMINATE_PROCESS,       // Fatal error - kill process
    DEBUG_BREAK,             // Break into debugger
    PASS_TO_NEXT_HANDLER     // Pass to next handler
};

// =============================================================================
// Patch Guard - Tracks active patch region
// =============================================================================

struct PatchGuard {
    uintptr_t patch_start;       // Start of patched region
    uintptr_t patch_end;         // End of patched region
    uint64_t epoch;              // Patch epoch
    bool active;                 // Is guard currently active?
    
    // Original bytes for emergency restore
    std::vector<uint8_t> original_bytes;
    
    PatchGuard() 
        : patch_start(0)
        , patch_end(0)
        , epoch(0)
        , active(false) 
    {}
    
    bool Contains(uintptr_t addr) const {
        return active && addr >= patch_start && addr < patch_end;
    }
};

// =============================================================================
// VEH_Watchdog - Crash detection and recovery
// =============================================================================

class VEH_Watchdog {
public:
    using ExceptionCallback = std::function<void(const ExceptionContext&)>;
    using RecoveryCallback = std::function<bool(uint64_t epoch)>;
    
    static VEH_Watchdog& Instance();
    
    // Initialize the watchdog
    bool Initialize();
    
    // Shutdown and unregister VEH
    void Shutdown();
    
    // -------------------------------------------------------------------------
    // Patch Guard Management
    // -------------------------------------------------------------------------
    
    // Activate guard around patch region
    bool GuardPatch(uintptr_t start, size_t size, uint64_t epoch, 
                    const std::vector<uint8_t>& original_bytes);
    
    // Deactivate guard (patch succeeded)
    bool ReleaseGuard(uint64_t epoch);
    
    // Check if address is within guarded region
    bool IsGuarded(uintptr_t addr) const;
    
    // Get active guard info
    bool GetActiveGuard(PatchGuard& out_guard) const;
    
    // -------------------------------------------------------------------------
    // Exception Handling
    // -------------------------------------------------------------------------
    
    // Set callback for exception notification
    void SetExceptionCallback(ExceptionCallback callback);
    
    // Set callback for recovery attempt
    void SetRecoveryCallback(RecoveryCallback callback);
    
    // Get last exception info
    bool GetLastException(ExceptionContext& out_ctx) const;
    
    // Clear last exception
    void ClearLastException();
    
    // -------------------------------------------------------------------------
    // Statistics
    // -------------------------------------------------------------------------
    
    size_t GetExceptionCount() const { return exception_count_.load(); }
    size_t GetRecoveryCount() const { return recovery_count_.load(); }
    size_t GetFailedRecoveryCount() const { return failed_recovery_count_.load(); }
    
    bool IsInitialized() const { return initialized_.load(); }
    
private:
    VEH_Watchdog() = default;
    ~VEH_Watchdog() = default;
    
    VEH_Watchdog(const VEH_Watchdog&) = delete;
    VEH_Watchdog& operator=(const VEH_Watchdog&) = delete;
    
    // VEH callback (static, calls Instance().HandleException)
    static LONG CALLBACK VectoredHandler(EXCEPTION_POINTERS* ExceptionInfo);
    
    // Instance exception handler
    LONG HandleException(EXCEPTION_POINTERS* info);
    
    // Attempt recovery
    bool AttemptRecovery(uint64_t epoch, const PatchGuard& guard);
    
    // Emergency restore (last resort)
    bool EmergencyRestore(const PatchGuard& guard);
    
    // Member variables
    std::atomic<bool> initialized_{false};
    PVOID veh_handle_{nullptr};
    
    mutable std::mutex guard_mutex_;
    PatchGuard active_guard_;
    
    ExceptionCallback exception_cb_;
    RecoveryCallback recovery_cb_;
    
    ExceptionContext last_exception_;
    mutable std::mutex exception_mutex_;
    
    std::atomic<size_t> exception_count_{0};
    std::atomic<size_t> recovery_count_{0};
    std::atomic<size_t> failed_recovery_count_{0};
    
    // Constants
    static constexpr DWORD VEH_FIRST_CHANCE = 1;
};

// =============================================================================
// ScopedPatchGuard - RAII for automatic guard management
// =============================================================================

class ScopedPatchGuard {
public:
    ScopedPatchGuard(uintptr_t start, size_t size, uint64_t epoch,
                     const std::vector<uint8_t>& original_bytes);
    ~ScopedPatchGuard();
    
    // Disable copy/move
    ScopedPatchGuard(const ScopedPatchGuard&) = delete;
    ScopedPatchGuard& operator=(const ScopedPatchGuard&) = delete;
    
    bool IsActive() const { return active_; }
    void Release();  // Manual release on success
    
private:
    uint64_t epoch_;
    bool active_;
};

// =============================================================================
// Convenience Macros
// =============================================================================

#define WATCHDOG_GUARD(addr, size, epoch, orig) \
    RawrXD::Sovereign::ScopedPatchGuard _guard(addr, size, epoch, orig)

#define WATCHDOG_INIT() \
    RawrXD::Sovereign::VEH_Watchdog::Instance().Initialize()

#define WATCHDOG_SHUTDOWN() \
    RawrXD::Sovereign::VEH_Watchdog::Instance().Shutdown()

} // namespace Sovereign
} // namespace RawrXD
