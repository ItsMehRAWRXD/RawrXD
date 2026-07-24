// ============================================================================
// HotPatcher.cpp - Runtime Code Modification Implementation
//
// The "Bottle" - Live patching without recompilation or restart
//
// Platform Support:
//   - Windows: VirtualProtect, FlushInstructionCache
//   - Linux: mprotect, __builtin___clear_cache
//   - macOS: vm_protect, sys_icache_invalidate
//
// Safety Mechanisms:
//   - Checksums for patch integrity
//   - Stack canaries for patch boundaries
//   - Automatic rollback on crash
//   - Memory protection during writes
//
// ============================================================================

#include "HotPatcher.hpp"
#include "HotPatcherSafety.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <random>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace Deep2 {

// ============================================================================
// Platform-Specific Memory Operations
// ============================================================================

class MemoryProtector {
public:
    static bool makeWritable(void* addr, size_t len) {
#ifdef _WIN32
        DWORD oldProtect;
        return VirtualProtect(addr, len, PAGE_EXECUTE_READWRITE, &oldProtect) != 0;
#else
        size_t pageSize = sysconf(_SC_PAGESIZE);
        void* pageStart = (void*)(((uintptr_t)addr + pageSize - 1) & ~(pageSize - 1));
        size_t pageLen = len + ((uintptr_t)addr - (uintptr_t)pageStart);
        return mprotect(pageStart, pageLen, PROT_READ | PROT_WRITE | PROT_EXEC) == 0;
#endif
    }
    
    static bool restoreProtection(void* addr, size_t len, int prot) {
#ifdef _WIN32
        DWORD oldProtect;
        DWORD winProt = (prot == 0) ? PAGE_EXECUTE_READ : PAGE_EXECUTE_READWRITE;
        return VirtualProtect(addr, len, winProt, &oldProtect) != 0;
#else
        size_t pageSize = sysconf(_SC_PAGESIZE);
        void* pageStart = (void*)(((uintptr_t)addr + pageSize - 1) & ~(pageSize - 1));
        size_t pageLen = len + ((uintptr_t)addr - (uintptr_t)pageStart);
        int flags = (prot == 0) ? (PROT_READ | PROT_EXEC) : (PROT_READ | PROT_WRITE | PROT_EXEC);
        return mprotect(pageStart, pageLen, flags) == 0;
#endif
    }
    
    static void flushCache(void* addr, size_t len) {
#ifdef _WIN32
        FlushInstructionCache(GetCurrentProcess(), addr, len);
#elif defined(__APPLE__)
        sys_icache_invalidate(addr, len);
#else
        __builtin___clear_cache((char*)addr, (char*)addr + len);
#endif
    }
};

// ============================================================================
// Trampoline Allocator (for calling original functions)
// ============================================================================

class TrampolineAllocator {
public:
    static constexpr size_t TRAMPOLINE_SIZE = 32;
    static constexpr size_t POOL_SIZE = 1024 * 1024;  // 1MB
    
    TrampolineAllocator() {
        pool_ = allocatePool();
        current_ = pool_;
    }
    
    ~TrampolineAllocator() {
        if (pool_) {
#ifdef _WIN32
            VirtualFree(pool_, 0, MEM_RELEASE);
#else
            munmap(pool_, POOL_SIZE);
#endif
        }
    }
    
    void* allocate() {
        if (!pool_) return nullptr;
        
        std::lock_guard<std::mutex> lock(mutex_);
        
        if ((uintptr_t)current_ >= (uintptr_t)pool_ + POOL_SIZE) {
            return nullptr;  // Pool exhausted
        }
        
        void* result = current_;
        current_ = (void*)((uintptr_t)current_ + TRAMPOLINE_SIZE);
        return result;
    }
    
private:
    void* pool_ = nullptr;
    void* current_ = nullptr;
    std::mutex mutex_;
    
    void* allocatePool() {
#ifdef _WIN32
        return VirtualAlloc(nullptr, POOL_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#else
        void* ptr = mmap(nullptr, POOL_SIZE, PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        return (ptr == MAP_FAILED) ? nullptr : ptr;
#endif
    }
};

// ============================================================================
// Patch Implementation
// ============================================================================

struct PatchImpl {
    PatchMetadata metadata;
    PatchStatus status = PatchStatus::PENDING;
    
    // Type-specific data (no unions with non-trivial types)
    struct {
        void* target;
        void* replacement;
        void* trampoline;
        uint8_t originalBytes[16];
        size_t patchSize;
    } funcHook;
    
    struct {
        void* oldKernelPtr;
        void* newKernelPtr;
        void** vtableSlot;
    } kernelReplace;
    
    struct {
        DecoderModePatch::Mode mode;
        DecoderModePatch::Config config;
    } decoderMode;
    
    // Metrics
    PatchMetrics metrics;
    std::chrono::steady_clock::time_point applyTime;
};

// ============================================================================
// HotPatcher Implementation
// ============================================================================

class HotPatcher::Impl {
public:
    std::unordered_map<std::string, std::unique_ptr<PatchImpl>> patches;
    std::unordered_map<std::string, std::string> activeKernels;
    std::unordered_map<std::string, std::string> abTests;
    
    TrampolineAllocator trampolineAlloc;
    std::mutex mutex;
    
    std::atomic<bool> autoRollback{true};
    std::atomic<uint64_t> maxApplyTimeMs{1000};
    
    bool initialized = false;
    
    // Restore points
    struct RestorePoint {
        std::string id;
        std::string description;
        uint64_t timestamp;
        std::vector<std::string> activePatches;
    };
    std::vector<RestorePoint> restorePoints;
    
    bool initialize() {
        if (initialized) return true;
        
        // Pre-allocate trampolines
        if (!trampolineAlloc.allocate()) {
            printf("[HotPatcher] ERROR: Failed to allocate trampoline pool\n");
            return false;
        }
        
        // Safety: Initialize crash recovery
        CrashRecovery::initialize([](const CrashRecovery::CrashContext& ctx) {
            printf("[SAFETY] Crash detected during patch operation!\n");
            printf("  Patch: %s\n", ctx.patchId.c_str());
            printf("  Operation: %s\n", ctx.operation.c_str());
            printf("  Type: %d\n", static_cast<int>(ctx.type));
            
            // Auto-rollback if enabled
            if (GetHotPatcher().isAutoRollbackEnabled()) {
                printf("[SAFETY] Initiating emergency rollback...\n");
                GetHotPatcher().emergencyRollback();
            }
        });
        
        initialized = true;
        printf("[HotPatcher] Initialized - The Bottle is ready (with safety systems)\n");
        return true;
    }
    
    void shutdown() {
        if (!initialized) return;
        
        // Rollback all active patches
        std::vector<std::string> active;
        for (auto& [id, patch] : patches) {
            if (patch->status == PatchStatus::ACTIVE) {
                active.push_back(id);
            }
        }
        
        for (const auto& id : active) {
            rollbackPatch(id);
        }
        
        patches.clear();
        initialized = false;
        printf("[HotPatcher] Shutdown complete\n");
    }
    
    // Generate unique patch ID
    std::string generatePatchId() {
        static std::random_device rd;
        static std::mt19937_64 gen(rd());
        static std::uniform_int_distribution<uint64_t> dis;
        
        uint64_t id = dis(gen);
        std::stringstream ss;
        ss << "patch_" << std::hex << std::setw(16) << std::setfill('0') << id;
        return ss.str();
    }
    
    // Validate a patch
    ValidationResult validatePatch(const std::string& patchId) {
        ValidationResult result;
        result.passed = false;
        
        std::lock_guard<std::mutex> lock(mutex);
        
        auto it = patches.find(patchId);
        if (it == patches.end()) {
            result.errors.push_back("Patch not found: " + patchId);
            return result;
        }
        
        auto& patch = it->second;
        patch->status = PatchStatus::VALIDATING;
        
        // Check dependencies
        for (const auto& dep : patch->metadata.dependencies) {
            auto depIt = patches.find(dep);
            if (depIt == patches.end() || depIt->second->status != PatchStatus::ACTIVE) {
                result.errors.push_back("Dependency not met: " + dep);
                result.dependenciesMet = false;
            }
        }
        if (result.dependenciesMet) {
            result.dependenciesMet = true;
        }
        
        // Check conflicts
        for (const auto& conflict : patch->metadata.conflicts) {
            auto confIt = patches.find(conflict);
            if (confIt != patches.end() && confIt->second->status == PatchStatus::ACTIVE) {
                result.errors.push_back("Conflict with active patch: " + conflict);
                result.noConflicts = false;
            }
        }
        if (result.noConflicts) {
            result.noConflicts = true;
        }
        
        // Verify checksum using SHA-256
        if (!patch->metadata.checksum.empty()) {
            SHA256Checksum::Hash currentHash = SHA256Checksum::compute(
                patch->code.data(), patch->code.size());
            SHA256Checksum::Hash expectedHash = SHA256Checksum::fromString(patch->metadata.checksum);
            result.checksumValid = SHA256Checksum::equal(currentHash, expectedHash);
            if (!result.checksumValid) {
                result.errors.push_back("Checksum mismatch for patch: " + patchId);
            }
        } else {
            result.checksumValid = true;  // No checksum provided, skip
        }
        
        // Check memory availability
        auto preFlight = PatchSafety::runPreFlight(patchId);
        result.memoryAvailable = preFlight.memoryAvailable;
        if (!preFlight.memoryAvailable) {
            result.errors.push_back("Insufficient memory for patch");
        }
        
        // Check stack space
        if (!preFlight.stackSpaceAvailable) {
            result.errors.push_back("Insufficient stack space");
        }
        
        // Calculate risk score using safety system
        result.riskScore = PatchSafety::calculateRiskScore(patchId);
        if (result.riskScore > 0.8f) {
            result.warnings.push_back("High risk patch (score: " + 
                std::to_string(result.riskScore) + ")");
        }
        
        // Additional risk factors
        if (patch->metadata.type == PatchType::BINARY_PATCH) {
            result.riskScore += 0.5f;
        }
        if (!patch->metadata.canRollback) {
            result.riskScore += 0.3f;
        }
        
        // Predict performance
        result.predictedSpeedup = patch->metadata.expectedSpeedup;
        result.predictedMemoryOverhead = patch->metadata.maxMemoryOverhead;
        
        result.passed = result.errors.empty();
        if (result.passed) {
            patch->status = PatchStatus::READY;
        } else {
            patch->status = PatchStatus::FAILED;
        }
        
        return result;
    }
    
    // Apply a function hook patch
    bool applyFunctionHook(const std::string& patchId) {
        auto it = patches.find(patchId);
        if (it == patches.end()) return false;
        
        auto& patch = it->second;
        if (patch->status != PatchStatus::READY) return false;
        
        // Safety: Use RAII guard for crash recovery
        PatchOperationGuard guard(patchId, "applyFunctionHook");
        
        // Safety: Start watchdog timer (5 second timeout)
        ScopedWatchdog watchdog(5000, [patchId]() {
            printf("[SAFETY] Watchdog timeout during patch application: %s\n", patchId.c_str());
            // Trigger emergency rollback
            GetHotPatcher().emergencyRollback();
        });
        
        patch->status = PatchStatus::APPLYING;
        
        auto startTime = std::chrono::steady_clock::now();
        
        // Make target memory writable
        void* target = patch->funcHook.target;
        size_t patchSize = patch->funcHook.patchSize;
        
        if (!MemoryProtector::makeWritable(target, patchSize)) {
            patch->status = PatchStatus::FAILED;
            return false;
        }
        
        // Safety: Save original bytes with checksum
        memcpy(patch->funcHook.originalBytes, target, patchSize);
        patch->metadata.checksum = SHA256Checksum::toString(
            SHA256Checksum::compute(target, patchSize));
        
        // Create trampoline (for calling original)
        void* trampoline = trampolineAlloc.allocate();
        if (!trampoline) {
            patch->status = PatchStatus::FAILED;
            return false;
        }
        
        // Write trampoline: jmp to original code after patch
        // x64: mov rax, addr; jmp rax
        uint8_t trampCode[] = {
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, imm64
            0xFF, 0xE0                                                      // jmp rax
        };
        uintptr_t origAddr = (uintptr_t)target + patchSize;
        memcpy(trampCode + 2, &origAddr, 8);
        memcpy(trampoline, trampCode, sizeof(trampCode));
        
        patch->funcHook.trampoline = trampoline;
        
        // Write patch: jmp to replacement
        uint8_t patchCode[] = {
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // mov rax, imm64
            0xFF, 0xE0                                                      // jmp rax
        };
        uintptr_t replAddr = (uintptr_t)patch->funcHook.replacement;
        memcpy(patchCode + 2, &replAddr, 8);
        memcpy(target, patchCode, patchSize);
        
        // Flush instruction cache
        MemoryProtector::flushCache(target, patchSize);
        MemoryProtector::flushCache(trampoline, sizeof(trampCode));
        
        // Restore protection
        MemoryProtector::restoreProtection(target, patchSize, 0);
        
        auto endTime = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
        
        patch->status = PatchStatus::ACTIVE;
        patch->applyTime = startTime;
        patch->metadata.appliedAt = std::chrono::duration_cast<std::chrono::milliseconds>(
            startTime.time_since_epoch()).count();
        patch->metadata.durationMs = duration.count();
        
        // Safety: Mark operation as successful
        guard.markSuccess();
        
        printf("[HotPatcher] Applied function hook: %s (%s) in %llu ms\n",
               patch->metadata.name.c_str(), patchId.c_str(), duration.count());
        
        return true;
    }
    
    // Rollback a patch
    bool rollbackPatch(const std::string& patchId) {
        std::lock_guard<std::mutex> lock(mutex);
        
        auto it = patches.find(patchId);
        if (it == patches.end()) return false;
        
        auto& patch = it->second;
        if (patch->status != PatchStatus::ACTIVE) return false;
        
        switch (patch->metadata.type) {
            case PatchType::FUNCTION_HOOK: {
                void* target = patch->funcHook.target;
                size_t patchSize = patch->funcHook.patchSize;
                
                if (!MemoryProtector::makeWritable(target, patchSize)) {
                    return false;
                }
                
                // Restore original bytes
                memcpy(target, patch->funcHook.originalBytes, patchSize);
                MemoryProtector::flushCache(target, patchSize);
                MemoryProtector::restoreProtection(target, patchSize, 0);
                break;
            }
            
            case PatchType::KERNEL_REPLACE: {
                // Restore original kernel pointer
                if (patch->kernelReplace.vtableSlot) {
                    *patch->kernelReplace.vtableSlot = patch->kernelReplace.oldKernelPtr;
                }
                break;
            }
            
            default:
                break;
        }
        
        patch->status = PatchStatus::ROLLED_BACK;
        patch->metrics.rollbacks++;
        
        printf("[HotPatcher] Rolled back patch: %s (%s)\n",
               patch->metadata.name.c_str(), patchId.c_str());
        
        return true;
    }
};

// ============================================================================
// HotPatcher Public API
// ============================================================================

HotPatcher::HotPatcher() : impl_(std::make_unique<Impl>()) {}
HotPatcher::~HotPatcher() = default;

bool HotPatcher::initialize() {
    return impl_->initialize();
}

void HotPatcher::shutdown() {
    impl_->shutdown();
}

// Register patches
template<typename FuncType>
std::string HotPatcher::registerFunctionHook(
    const std::string& name,
    FuncType* targetFunc,
    FuncType* replacementFunc,
    const PatchMetadata& meta) {
    
    std::lock_guard<std::mutex> lock(impl_->mutex);
    
    std::string patchId = impl_->generatePatchId();
    auto patch = std::make_unique<PatchImpl>();
    
    patch->metadata = meta;
    patch->metadata.id = patchId;
    patch->metadata.name = name;
    patch->metadata.type = PatchType::FUNCTION_HOOK;
    patch->metadata.createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    patch->funcHook.target = (void*)targetFunc;
    patch->funcHook.replacement = (void*)replacementFunc;
    patch->funcHook.patchSize = 12;  // x64: mov rax, addr; jmp rax
    
    impl_->patches[patchId] = std::move(patch);
    
    printf("[HotPatcher] Registered function hook: %s (%s)\n", name.c_str(), patchId.c_str());
    return patchId;
}

std::string HotPatcher::registerKernelReplacement(
    const KernelReplacement& kernel,
    const PatchMetadata& meta) {
    
    std::lock_guard<std::mutex> lock(impl_->mutex);
    
    std::string patchId = impl_->generatePatchId();
    auto patch = std::make_unique<PatchImpl>();
    
    patch->metadata = meta;
    patch->metadata.id = patchId;
    patch->metadata.type = PatchType::KERNEL_REPLACE;
    patch->metadata.createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    patch->kernelReplace.oldKernelPtr = kernel.oldKernelPtr;
    patch->kernelReplace.newKernelPtr = kernel.newKernelPtr;
    patch->kernelReplace.vtableSlot = kernel.vtableSlot;
    
    impl_->patches[patchId] = std::move(patch);
    
    printf("[HotPatcher] Registered kernel replacement: %s (%s)\n",
           kernel.kernelName.c_str(), patchId.c_str());
    return patchId;
}

std::string HotPatcher::registerDecoderMode(
    const DecoderModePatch& mode,
    const PatchMetadata& meta) {
    
    std::lock_guard<std::mutex> lock(impl_->mutex);
    
    std::string patchId = impl_->generatePatchId();
    auto patch = std::make_unique<PatchImpl>();
    
    patch->metadata = meta;
    patch->metadata.id = patchId;
    patch->metadata.type = PatchType::DECODER_MODE;
    patch->metadata.createdAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    patch->decoderMode.mode = mode.targetMode;
    patch->decoderMode.config = mode.config;
    
    impl_->patches[patchId] = std::move(patch);
    
    printf("[HotPatcher] Registered decoder mode: %d (%s)\n",
           (int)mode.targetMode, patchId.c_str());
    return patchId;
}

// Lifecycle
ValidationResult HotPatcher::validate(const std::string& patchId) {
    return impl_->validatePatch(patchId);
}

bool HotPatcher::apply(const std::string& patchId) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    
    auto it = impl_->patches.find(patchId);
    if (it == impl_->patches.end()) return false;
    
    auto& patch = it->second;
    
    switch (patch->metadata.type) {
        case PatchType::FUNCTION_HOOK:
            return impl_->applyFunctionHook(patchId);
            
        case PatchType::KERNEL_REPLACE:
            // Apply kernel replacement
            if (patch->kernelReplace.vtableSlot) {
                *patch->kernelReplace.vtableSlot = patch->kernelReplace.newKernelPtr;
                patch->status = PatchStatus::ACTIVE;
                impl_->activeKernels[patch->metadata.id] = patchId;
                return true;
            }
            return false;
            
        case PatchType::DECODER_MODE:
            // Decoder mode switches are handled by the engine
            patch->status = PatchStatus::ACTIVE;
            return true;
            
        default:
            return false;
    }
}

bool HotPatcher::rollback(const std::string& patchId) {
    return impl_->rollbackPatch(patchId);
}

// Query
PatchStatus HotPatcher::getStatus(const std::string& patchId) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    
    auto it = impl_->patches.find(patchId);
    if (it == impl_->patches.end()) return PatchStatus::FAILED;
    return it->second->status;
}

std::vector<std::string> HotPatcher::listPatches(PatchStatus filter) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    
    std::vector<std::string> result;
    for (const auto& [id, patch] : impl_->patches) {
        if (filter == PatchStatus::ACTIVE || patch->status == filter) {
            result.push_back(id);
        }
    }
    return result;
}

bool HotPatcher::isActive(const std::string& patchId) {
    return getStatus(patchId) == PatchStatus::ACTIVE;
}

// Safety
void HotPatcher::setAutoRollback(bool enabled) {
    impl_->autoRollback = enabled;
}

bool HotPatcher::isAutoRollbackEnabled() const {
    return impl_->autoRollback.load();
}

bool HotPatcher::emergencyRollback() {
    printf("[HotPatcher] EMERGENCY ROLLBACK initiated\n");
    
    std::vector<std::string> active;
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        for (const auto& [id, patch] : impl_->patches) {
            if (patch->status == PatchStatus::ACTIVE) {
                active.push_back(id);
            }
        }
    }
    
    bool success = true;
    for (const auto& id : active) {
        if (!rollback(id)) {
            success = false;
        }
    }
    
    printf("[HotPatcher] Emergency rollback %s\n", success ? "COMPLETE" : "PARTIAL");
    return success;
}

// Statistics
void HotPatcher::printStatus() {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║              HotPatcher Status - The Bottle                    ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    
    size_t total = impl_->patches.size();
    size_t active = 0, ready = 0, failed = 0, rolled = 0;
    
    for (const auto& [id, patch] : impl_->patches) {
        switch (patch->status) {
            case PatchStatus::ACTIVE: active++; break;
            case PatchStatus::READY: ready++; break;
            case PatchStatus::FAILED: failed++; break;
            case PatchStatus::ROLLED_BACK: rolled++; break;
            default: break;
        }
    }
    
    printf("║ Total Patches:    %3zu                                          ║\n", total);
    printf("║ Active:           %3zu                                          ║\n", active);
    printf("║ Ready:            %3zu                                          ║\n", ready);
    printf("║ Failed:           %3zu                                          ║\n", failed);
    printf("║ Rolled Back:      %3zu                                          ║\n", rolled);
    printf("║ Auto-Rollback:    %s                                          ║\n",
           impl_->autoRollback ? "ENABLED " : "DISABLED");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
    
    if (active > 0) {
        printf("Active Patches:\n");
        for (const auto& [id, patch] : impl_->patches) {
            if (patch->status == PatchStatus::ACTIVE) {
                printf("  [%s] %s\n", id.c_str(), patch->metadata.name.c_str());
            }
        }
        printf("\n");
    }
}

// Global singleton
HotPatcher& GetHotPatcher() {
    static HotPatcher instance;
    return instance;
}

} // namespace Deep2
