#include "VEH_Watchdog.hpp"
#include <windows.h>
#include <dbghelp.h>
#include <iostream>
#include <sstream>

#pragma comment(lib, "dbghelp.lib")

namespace RawrXD {
namespace Sovereign {

// =============================================================================
// Singleton
// =============================================================================

VEH_Watchdog& VEH_Watchdog::Instance() {
    static VEH_Watchdog instance;
    return instance;
}

// =============================================================================
// Initialization
// =============================================================================

bool VEH_Watchdog::Initialize() {
    if (initialized_.exchange(true)) {
        return true;  // Already initialized
    }
    
    // Register vectored exception handler (first chance)
    veh_handle_ = AddVectoredExceptionHandler(VEH_FIRST_CHANCE, VectoredHandler);
    
    if (!veh_handle_) {
        initialized_.store(false);
        return false;
    }
    
    return true;
}

void VEH_Watchdog::Shutdown() {
    if (!initialized_.exchange(false)) {
        return;
    }
    
    if (veh_handle_) {
        RemoveVectoredExceptionHandler(veh_handle_);
        veh_handle_ = nullptr;
    }
}

// =============================================================================
// VEH Callback
// =============================================================================

LONG CALLBACK VEH_Watchdog::VectoredHandler(EXCEPTION_POINTERS* ExceptionInfo) {
    return Instance().HandleException(ExceptionInfo);
}

LONG VEH_Watchdog::HandleException(EXCEPTION_POINTERS* info) {
    exception_count_.fetch_add(1, std::memory_order_relaxed);
    
    // Capture exception context
    EXCEPTION_RECORD* record = info->ExceptionRecord;
    CONTEXT* context = info->ContextRecord;
    
    // Check if exception is within guarded region
    uintptr_t fault_addr = reinterpret_cast<uintptr_t>(record->ExceptionAddress);
    
    std::lock_guard<std::mutex> lock(guard_mutex_);
    
    if (!active_guard_.Contains(fault_addr)) {
        // Exception outside our patch - pass to next handler
        return EXCEPTION_CONTINUE_SEARCH;
    }
    
    // Exception within guarded patch region - attempt recovery
    
    // Store exception info
    {
        std::lock_guard<std::mutex> exc_lock(exception_mutex_);
        last_exception_.timestamp = GetTickCount64();
        last_exception_.patch_epoch = active_guard_.epoch;
        last_exception_.faulting_address = fault_addr;
        memcpy(&last_exception_.exceptionRecord, record, sizeof(EXCEPTION_RECORD));
        memcpy(&last_exception_.contextRecord, context, sizeof(CONTEXT));
    }
    
    // Notify callback
    if (exception_cb_) {
        exception_cb_(last_exception_);
    }
    
    // Attempt recovery
    bool recovered = AttemptRecovery(active_guard_.epoch, active_guard_);
    
    if (recovered) {
        recovery_count_.fetch_add(1, std::memory_order_relaxed);
        
        // Modify context to return to safe point
        // This is architecture-specific - for x64, we modify RIP
        #ifdef _WIN64
        context->Rip = active_guard_.patch_start;  // Jump to start of patched region
        context->Rax = static_cast<DWORD64>(-1);     // Return error code
        #else
        context->Eip = active_guard_.patch_start;
        context->Eax = static_cast<DWORD>(-1);
        #endif
        
        // Clear the guard
        active_guard_.active = false;
        
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    
    // Recovery failed
    failed_recovery_count_.fetch_add(1, std::memory_order_relaxed);
    
    // Emergency restore as last resort
    if (EmergencyRestore(active_guard_)) {
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    
    // Fatal - cannot recover
    return EXCEPTION_CONTINUE_SEARCH;
}

// =============================================================================
// Patch Guard Management
// =============================================================================

bool VEH_Watchdog::GuardPatch(uintptr_t start, size_t size, uint64_t epoch,
                               const std::vector<uint8_t>& original_bytes) {
    std::lock_guard<std::mutex> lock(guard_mutex_);
    
    if (active_guard_.active) {
        // Another guard is active - release it first
        active_guard_.active = false;
    }
    
    active_guard_.patch_start = start;
    active_guard_.patch_end = start + size;
    active_guard_.epoch = epoch;
    active_guard_.original_bytes = original_bytes;
    active_guard_.active = true;
    
    return true;
}

bool VEH_Watchdog::ReleaseGuard(uint64_t epoch) {
    std::lock_guard<std::mutex> lock(guard_mutex_);
    
    if (!active_guard_.active || active_guard_.epoch != epoch) {
        return false;
    }
    
    active_guard_.active = false;
    active_guard_.original_bytes.clear();
    
    return true;
}

bool VEH_Watchdog::IsGuarded(uintptr_t addr) const {
    std::lock_guard<std::mutex> lock(guard_mutex_);
    return active_guard_.Contains(addr);
}

bool VEH_Watchdog::GetActiveGuard(PatchGuard& out_guard) const {
    std::lock_guard<std::mutex> lock(guard_mutex_);
    
    if (!active_guard_.active) {
        return false;
    }
    
    out_guard = active_guard_;
    return true;
}

// =============================================================================
// Recovery
// =============================================================================

bool VEH_Watchdog::AttemptRecovery(uint64_t epoch, const PatchGuard& guard) {
    // Call external recovery callback if set
    if (recovery_cb_) {
        return recovery_cb_(epoch);
    }
    
    // Default recovery: restore original bytes
    if (guard.original_bytes.empty()) {
        return false;
    }
    
    DWORD oldProtect;
    if (!VirtualProtect(reinterpret_cast<LPVOID>(guard.patch_start), 
                        guard.original_bytes.size(), 
                        PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }
    
    // Restore original bytes
    memcpy(reinterpret_cast<void*>(guard.patch_start), 
           guard.original_bytes.data(), 
           guard.original_bytes.size());
    
    VirtualProtect(reinterpret_cast<LPVOID>(guard.patch_start), 
                   guard.original_bytes.size(), 
                   oldProtect, &oldProtect);
    
    FlushInstructionCache(GetCurrentProcess(), 
                          reinterpret_cast<LPCVOID>(guard.patch_start), 
                          guard.original_bytes.size());
    
    return true;
}

bool VEH_Watchdog::EmergencyRestore(const PatchGuard& guard) {
    // Last resort - try to restore with minimal operations
    if (guard.original_bytes.empty()) {
        return false;
    }
    
    __try {
        // Direct memory write (dangerous but we're crashing anyway)
        volatile uint8_t* dest = reinterpret_cast<volatile uint8_t*>(guard.patch_start);
        for (size_t i = 0; i < guard.original_bytes.size(); ++i) {
            dest[i] = guard.original_bytes[i];
        }
        return true;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// =============================================================================
// Exception Info
// =============================================================================

bool VEH_Watchdog::GetLastException(ExceptionContext& out_ctx) const {
    std::lock_guard<std::mutex> lock(exception_mutex_);
    
    if (last_exception_.timestamp == 0) {
        return false;
    }
    
    out_ctx = last_exception_;
    return true;
}

void VEH_Watchdog::ClearLastException() {
    std::lock_guard<std::mutex> lock(exception_mutex_);
    last_exception_.timestamp = 0;
}

// =============================================================================
// Callbacks
// =============================================================================

void VEH_Watchdog::SetExceptionCallback(ExceptionCallback callback) {
    exception_cb_ = callback;
}

void VEH_Watchdog::SetRecoveryCallback(RecoveryCallback callback) {
    recovery_cb_ = callback;
}

// =============================================================================
// ScopedPatchGuard Implementation
// =============================================================================

ScopedPatchGuard::ScopedPatchGuard(uintptr_t start, size_t size, uint64_t epoch,
                                     const std::vector<uint8_t>& original_bytes)
    : epoch_(epoch)
    , active_(false)
{
    active_ = VEH_Watchdog::Instance().GuardPatch(start, size, epoch, original_bytes);
}

ScopedPatchGuard::~ScopedPatchGuard() {
    if (active_) {
        // Attempt automatic rollback if not manually released
        VEH_Watchdog::Instance().ReleaseGuard(epoch_);
    }
}

void ScopedPatchGuard::Release() {
    if (active_) {
        VEH_Watchdog::Instance().ReleaseGuard(epoch_);
        active_ = false;
    }
}

} // namespace Sovereign
} // namespace RawrXD
