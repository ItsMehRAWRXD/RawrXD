// ============================================================================
// NEVMPHotPatcher.hpp - .nevmp HotPatcher Integration
// Self-modifying code substrate for the Sovereign runtime
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace Sovereign {

// NEVMP patch descriptor
struct NEVMPPatch {
    uint64_t targetAddress;
    std::vector<uint8_t> expectedBytes;
    std::vector<uint8_t> replacementBytes;
    std::string moduleName;
    std::string reason;
    uint32_t flags;
    bool isActive;
    uint64_t appliedAt;
};

// NEVMP transaction
struct NEVMPTransaction {
    uint64_t id;
    std::vector<NEVMPPatch> patches;
    bool committed;
    bool rolledBack;
    uint64_t timestamp;
};

// NEVMP statistics
struct NEVMPStats {
    uint64_t totalPatches;
    uint64_t activePatches;
    uint64_t successfulPatches;
    uint64_t failedPatches;
    uint64_t rollbacks;
    uint64_t totalBytesPatched;
    double avgPatchTimeUs;
};

// NEVMP HotPatcher
class NEVMPHotPatcher {
public:
    NEVMPHotPatcher();
    ~NEVMPHotPatcher();

    // Initialize
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    // Patch operations
    uint64_t ApplyPatch(const NEVMPPatch& patch);
    bool RollbackPatch(uint64_t patchId);
    bool RollbackTransaction(uint64_t transactionId);
    bool CommitTransaction(uint64_t transactionId);

    // Transaction management
    uint64_t BeginTransaction();
    bool AddToTransaction(uint64_t transactionId, const NEVMPPatch& patch);
    bool EndTransaction(uint64_t transactionId, bool commit);

    // Memory protection
    bool SetPageProtection(uint64_t address, size_t size, uint32_t protection);
    bool RestorePageProtection(uint64_t address, size_t size);

    // Cache management
    void FlushInstructionCache(uint64_t address, size_t size);
    void FlushAllCaches();

    // Validation
    bool ValidatePatch(const NEVMPPatch& patch);
    bool VerifyBytes(uint64_t address, const std::vector<uint8_t>& expected);
    std::vector<uint8_t> ReadBytes(uint64_t address, size_t size);

    // Module resolution
    uint64_t ResolveSymbol(const std::string& module, const std::string& symbol);
    uint64_t GetModuleBase(const std::string& module);
    size_t GetModuleSize(const std::string& module);

    // Telemetry
    NEVMPStats GetStats() const;
    void ResetStats();
    void SetPatchCallback(std::function<void(const NEVMPPatch&, bool)> callback);

    // Persistence
    bool SavePatchLog(const std::string& path);
    bool LoadPatchLog(const std::string& path);

    // Safety
    bool EnableSafety(bool enabled);
    bool IsSafe() const { return safetyEnabled_; }

private:
    bool initialized_ = false;
    bool safetyEnabled_ = true;
    
    std::vector<NEVMPPatch> patches_;
    std::vector<NEVMPTransaction> transactions_;
    NEVMPStats stats_;
    uint64_t nextPatchId_ = 1;
    uint64_t nextTransactionId_ = 1;
    
    std::function<void(const NEVMPPatch&, bool)> patchCallback_;
    mutable std::mutex mutex_;
    
    // Win32 API wrappers
    bool WriteMemory(uint64_t address, const void* data, size_t size);
    bool ReadMemory(uint64_t address, void* data, size_t size);
    bool VirtualProtect(uint64_t address, size_t size, uint32_t newProtect, uint32_t* oldProtect);
};

// VEH (Vectored Exception Handler) Watchdog
class VEHWatchdog {
public:
    VEHWatchdog();
    ~VEHWatchdog();

    // Initialize
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    // Exception handling
    void SetExceptionHandler(std::function<bool(uint32_t, uint64_t)> handler);
    void SetFaultHandler(std::function<void(uint64_t, uint32_t)> handler);

    // Memory access violation handling
    void HandleAccessViolation(uint64_t address, uint32_t type);
    void HandlePageFault(uint64_t address);

    // Breakpoint handling
    void SetBreakpointHandler(std::function<void(uint64_t)> handler);
    void HandleBreakpoint(uint64_t address);

    // Statistics
    struct VEHStats {
        uint64_t totalExceptions;
        uint64_t accessViolations;
        uint64_t breakpoints;
        uint64_t pageFaults;
        uint64_t handledExceptions;
        uint64_t unhandledExceptions;
    };
    VEHStats GetStats() const { return stats_; }
    void ResetStats();

private:
    bool initialized_ = false;
    void* vehHandle_ = nullptr;
    VEHStats stats_;
    
    std::function<bool(uint32_t, uint64_t)> exceptionHandler_;
    std::function<void(uint64_t, uint32_t)> faultHandler_;
    std::function<void(uint64_t)> breakpointHandler_;
    
    static LONG CALLBACK VectoredHandler(PEXCEPTION_POINTERS exceptionInfo);
    LONG HandleException(PEXCEPTION_POINTERS exceptionInfo);
};

} // namespace Sovereign
