// ============================================================================
// NEVMPHotPatcher.cpp - .nevmp HotPatcher Integration Implementation
// ============================================================================

#include "NEVMPHotPatcher.hpp"
#include <cstring>
#include <iostream>
#include <fstream>

namespace Sovereign {

NEVMPHotPatcher::NEVMPHotPatcher() = default;
NEVMPHotPatcher::~NEVMPHotPatcher() {
    Shutdown();
}

bool NEVMPHotPatcher::Initialize() {
    initialized_ = true;
    return true;
}

void NEVMPHotPatcher::Shutdown() {
    // Rollback all active patches
    for (auto& patch : patches_) {
        if (patch.isActive) {
            RollbackPatch(patch.targetAddress);
        }
    }
    patches_.clear();
    initialized_ = false;
}

uint64_t NEVMPHotPatcher::ApplyPatch(const NEVMPPatch& patch) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (!initialized_) return 0;
    
    // Validate patch
    if (!ValidatePatch(patch)) {
        stats_.failedPatches++;
        return 0;
    }
    
    // Verify expected bytes
    if (!VerifyBytes(patch.targetAddress, patch.expectedBytes)) {
        stats_.failedPatches++;
        if (patchCallback_) patchCallback_(patch, false);
        return 0;
    }
    
    // Change page protection
    uint32_t oldProtect = 0;
    if (!VirtualProtect(patch.targetAddress, patch.replacementBytes.size(), 
                        PAGE_EXECUTE_READWRITE, &oldProtect)) {
        stats_.failedPatches++;
        return 0;
    }
    
    // Write replacement bytes
    if (!WriteMemory(patch.targetAddress, patch.replacementBytes.data(), 
                     patch.replacementBytes.size())) {
        VirtualProtect(patch.targetAddress, patch.replacementBytes.size(), oldProtect, &oldProtect);
        stats_.failedPatches++;
        return 0;
    }
    
    // Flush instruction cache
    FlushInstructionCache(patch.targetAddress, patch.replacementBytes.size());
    
    // Restore protection
    VirtualProtect(patch.targetAddress, patch.replacementBytes.size(), oldProtect, &oldProtect);
    
    // Record patch
    NEVMPPatch recorded = patch;
    recorded.isActive = true;
    recorded.appliedAt = GetTickCount64();
    
    uint64_t patchId = nextPatchId_++;
    patches_.push_back(recorded);
    
    stats_.totalPatches++;
    stats_.activePatches++;
    stats_.successfulPatches++;
    stats_.totalBytesPatched += patch.replacementBytes.size();
    
    if (patchCallback_) patchCallback_(recorded, true);
    
    return patchId;
}

bool NEVMPHotPatcher::RollbackPatch(uint64_t patchId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    for (auto& patch : patches_) {
        if (patch.targetAddress == patchId && patch.isActive) {
            // Write original bytes back
            uint32_t oldProtect = 0;
            VirtualProtect(patch.targetAddress, patch.expectedBytes.size(), 
                          PAGE_EXECUTE_READWRITE, &oldProtect);
            
            WriteMemory(patch.targetAddress, patch.expectedBytes.data(), 
                       patch.expectedBytes.size());
            
            FlushInstructionCache(patch.targetAddress, patch.expectedBytes.size());
            VirtualProtect(patch.targetAddress, patch.expectedBytes.size(), oldProtect, &oldProtect);
            
            patch.isActive = false;
            stats_.activePatches--;
            stats_.rollbacks++;
            return true;
        }
    }
    return false;
}

uint64_t NEVMPHotPatcher::BeginTransaction() {
    NEVMPTransaction tx;
    tx.id = nextTransactionId_++;
    tx.committed = false;
    tx.rolledBack = false;
    tx.timestamp = GetTickCount64();
    transactions_.push_back(tx);
    return tx.id;
}

bool NEVMPHotPatcher::AddToTransaction(uint64_t transactionId, const NEVMPPatch& patch) {
    for (auto& tx : transactions_) {
        if (tx.id == transactionId && !tx.committed && !tx.rolledBack) {
            tx.patches.push_back(patch);
            return true;
        }
    }
    return false;
}

bool NEVMPHotPatcher::EndTransaction(uint64_t transactionId, bool commit) {
    for (auto& tx : transactions_) {
        if (tx.id == transactionId) {
            if (commit) {
                for (const auto& patch : tx.patches) {
                    ApplyPatch(patch);
                }
                tx.committed = true;
            } else {
                tx.rolledBack = true;
            }
            return true;
        }
    }
    return false;
}

bool NEVMPHotPatcher::ValidatePatch(const NEVMPPatch& patch) {
    if (patch.targetAddress == 0) return false;
    if (patch.replacementBytes.empty()) return false;
    if (patch.expectedBytes.size() != patch.replacementBytes.size()) return false;
    if (patch.replacementBytes.size() > 4096) return false; // Max 4KB per patch
    return true;
}

bool NEVMPHotPatcher::VerifyBytes(uint64_t address, const std::vector<uint8_t>& expected) {
    std::vector<uint8_t> actual(expected.size());
    if (!ReadMemory(address, actual.data(), actual.size())) return false;
    return memcmp(actual.data(), expected.data(), expected.size()) == 0;
}

std::vector<uint8_t> NEVMPHotPatcher::ReadBytes(uint64_t address, size_t size) {
    std::vector<uint8_t> data(size);
    ReadMemory(address, data.data(), size);
    return data;
}

void NEVMPHotPatcher::FlushInstructionCache(uint64_t address, size_t size) {
    ::FlushInstructionCache(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address), size);
}

void NEVMPHotPatcher::FlushAllCaches() {
    // Flush entire instruction cache
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    ::FlushInstructionCache(GetCurrentProcess(), si.lpMinimumApplicationAddress,
                           reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress) - 
                           reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress));
}

bool NEVMPHotPatcher::WriteMemory(uint64_t address, const void* data, size_t size) {
    SIZE_T written;
    return WriteProcessMemory(GetCurrentProcess(), reinterpret_cast<LPVOID>(address), 
                             data, size, &written) && written == size;
}

bool NEVMPHotPatcher::ReadMemory(uint64_t address, void* data, size_t size) {
    SIZE_T read;
    return ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(address),
                            data, size, &read) && read == size;
}

bool NEVMPHotPatcher::VirtualProtect(uint64_t address, size_t size, uint32_t newProtect, uint32_t* oldProtect) {
    return ::VirtualProtect(reinterpret_cast<LPVOID>(address), size, newProtect, 
                          reinterpret_cast<PDWORD>(oldProtect)) != 0;
}

NEVMPStats NEVMPHotPatcher::GetStats() const {
    return stats_;
}

void NEVMPHotPatcher::ResetStats() {
    stats_ = NEVMPStats{};
}

bool NEVMPHotPatcher::SavePatchLog(const std::string& path) {
    std::ofstream file(path);
    if (!file) return false;
    
    for (const auto& patch : patches_) {
        file << patch.targetAddress << "|"
             << patch.moduleName << "|"
             << patch.reason << "|"
             << (patch.isActive ? "1" : "0") << "|"
             << patch.appliedAt << "\n";
    }
    return true;
}

bool NEVMPHotPatcher::LoadPatchLog(const std::string& path) {
    std::ifstream file(path);
    if (!file) return false;
    
    std::string line;
    while (std::getline(file, line)) {
        // Parse and restore patches
    }
    return true;
}

// ============================================================
// VEHWatchdog
// ============================================================

VEHWatchdog::VEHWatchdog() = default;
VEHWatchdog::~VEHWatchdog() {
    Shutdown();
}

bool VEHWatchdog::Initialize() {
    if (initialized_) return false;
    
    vehHandle_ = AddVectoredExceptionHandler(1, VectoredHandler);
    if (!vehHandle_) return false;
    
    initialized_ = true;
    return true;
}

void VEHWatchdog::Shutdown() {
    if (vehHandle_) {
        RemoveVectoredExceptionHandler(vehHandle_);
        vehHandle_ = nullptr;
    }
    initialized_ = false;
}

LONG CALLBACK VEHWatchdog::VectoredHandler(PEXCEPTION_POINTERS exceptionInfo) {
    // Find the VEHWatchdog instance
    // In production, use TLS or a global registry
    return EXCEPTION_CONTINUE_SEARCH;
}

LONG VEHWatchdog::HandleException(PEXCEPTION_POINTERS exceptionInfo) {
    stats_.totalExceptions++;
    
    uint32_t code = exceptionInfo->ExceptionRecord->ExceptionCode;
    uint64_t address = reinterpret_cast<uint64_t>(exceptionInfo->ExceptionRecord->ExceptionAddress);
    
    switch (code) {
        case EXCEPTION_ACCESS_VIOLATION:
            stats_.accessViolations++;
            HandleAccessViolation(
                exceptionInfo->ExceptionRecord->ExceptionInformation[1],
                exceptionInfo->ExceptionRecord->ExceptionInformation[0]);
            break;
            
        case EXCEPTION_BREAKPOINT:
        case EXCEPTION_SINGLE_STEP:
            stats_.breakpoints++;
            HandleBreakpoint(address);
            break;
            
        case EXCEPTION_GUARD_PAGE:
            stats_.pageFaults++;
            HandlePageFault(address);
            break;
    }
    
    if (exceptionHandler_ && exceptionHandler_(code, address)) {
        stats_.handledExceptions++;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    
    stats_.unhandledExceptions++;
    return EXCEPTION_CONTINUE_SEARCH;
}

void VEHWatchdog::HandleAccessViolation(uint64_t address, uint32_t type) {
    if (faultHandler_) {
        faultHandler_(address, type);
    }
}

void VEHWatchdog::HandlePageFault(uint64_t address) {
    // Could trigger memory aperture expansion
}

void VEHWatchdog::HandleBreakpoint(uint64_t address) {
    if (breakpointHandler_) {
        breakpointHandler_(address);
    }
}

} // namespace Sovereign
