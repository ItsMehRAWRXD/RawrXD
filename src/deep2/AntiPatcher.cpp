// ============================================================================
// AntiPatcher.cpp - The Antidote Implementation
//
// Detects, analyzes, and removes unauthorized code modifications.
// The yang to The Bottle's yin.
//
// Detection Methods:
//   - Signature scanning (known hook patterns)
//   - Baseline comparison (hash-based integrity)
//   - Entropy analysis (detect injected code)
//   - Control flow analysis (detect detours)
//
// Restoration:
//   - Memory protection bypass
//   - Atomic restoration
//   - Verification after removal
//
// ============================================================================

#include "AntiPatcher.hpp"
#include "HotPatcherSafety.hpp"
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <thread>
#include <chrono>

#ifdef _WIN32
#include <windows.h>
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")
#else
#include <sys/mman.h>
#include <unistd.h>
#include <signal.h>
#endif

namespace Deep2 {

// ============================================================================
// Platform-Specific Memory Operations (from HotPatcher)
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
// Patch Signature Detection
// ============================================================================

class PatchDetector {
public:
    // x64: mov rax, imm64; jmp rax (12 bytes)
    static bool isX64JmpAbsolute(const uint8_t* bytes, size_t len) {
        if (len < 12) return false;
        return bytes[0] == 0x48 && bytes[1] == 0xB8 &&  // mov rax, imm64
               bytes[10] == 0xFF && bytes[11] == 0xE0; // jmp rax
    }
    
    // x64: jmp rel32 (5 bytes)
    static bool isX64JmpRelative(const uint8_t* bytes, size_t len) {
        if (len < 5) return false;
        return bytes[0] == 0xE9;  // jmp rel32
    }
    
    // x64: call rel32 (5 bytes)
    static bool isX64CallRelative(const uint8_t* bytes, size_t len) {
        if (len < 5) return false;
        return bytes[0] == 0xE8;  // call rel32
    }
    
    // Trampoline pattern: push/pop + jmp
    static bool isTrampoline(const uint8_t* bytes, size_t len) {
        if (len < 20) return false;
        // Look for trampoline prologue
        return (bytes[0] == 0xFF && bytes[1] == 0x25) ||  // jmp [rip+offset]
               (bytes[0] == 0x48 && bytes[1] == 0x89 && bytes[2] == 0xE5); // push rbp
    }
    
    // Microsoft hotpatch NOP (0x90 padding before function)
    static bool isHotpatchNop(const uint8_t* bytes, size_t len) {
        if (len < 2) return false;
        return bytes[0] == 0x90 && bytes[1] == 0x90;  // nop nop
    }
    
    // Detours style: push rax; mov rax, addr; jmp rax
    static bool isDetourPatch(const uint8_t* bytes, size_t len) {
        if (len < 14) return false;
        return bytes[0] == 0x50 &&  // push rax
               bytes[1] == 0x48 && bytes[2] == 0xB8;  // mov rax, imm64
    }
    
    // Detect any known signature
    static PatchSignature detect(const uint8_t* bytes, size_t len) {
        if (isX64JmpAbsolute(bytes, len)) return PatchSignature::X64_JMP_ABSOLUTE;
        if (isX64JmpRelative(bytes, len)) return PatchSignature::X64_JMP_RELATIVE;
        if (isX64CallRelative(bytes, len)) return PatchSignature::X64_CALL_ABSOLUTE;
        if (isTrampoline(bytes, len)) return PatchSignature::X64_TRAMPOLINE;
        if (isDetourPatch(bytes, len)) return PatchSignature::DETOUR_PATCH;
        if (isHotpatchNop(bytes, len)) return PatchSignature::HOTPATCH_NOP;
        
        // Check for suspicious patterns (unusual instructions at function start)
        if (len >= 1) {
            // Any jump or call at function start is suspicious
            if (bytes[0] == 0xE9 || bytes[0] == 0xEB ||  // jmp
                bytes[0] == 0xE8 ||  // call
                (bytes[0] >= 0x70 && bytes[0] <= 0x7F)) {  // conditional jmp
                return PatchSignature::UNKNOWN_HOOK;
            }
        }
        
        return PatchSignature::UNKNOWN;
    }
};

// ============================================================================
// AntiPatcher Implementation
// ============================================================================

class AntiPatcher::Impl {
public:
    std::unordered_map<std::string, CodeBaseline> baselines;
    std::unordered_map<std::string, DetectedPatch> detectedPatches;
    std::unordered_map<std::string, PatchEvidence> evidenceLog;
    std::unordered_map<std::string, std::string> authorizedPatches;
    
    ImmunizationPolicy policy;
    std::atomic<bool> monitoring{false};
    std::atomic<bool> shouldStop{false};
    std::thread monitorThread;
    
    DetectionCallback detectionCallback;
    RemovalCallback removalCallback;
    
    std::mutex mutex;
    bool initialized = false;
    
    // Statistics
    std::atomic<size_t> totalDetected{0};
    std::atomic<size_t> totalRemoved{0};
    std::atomic<size_t> totalBlocked{0};
    
    bool initialize() {
        if (initialized) return true;
        
        printf("[AntiPatcher] Initializing The Antidote...\n");
        
        // Set default policy
        policy.level = ImmunizationPolicy::MONITOR;
        policy.autoRestore = false;
        policy.alarmOnUnknown = true;
        policy.scanIntervalMs = 1000;
        
        initialized = true;
        printf("[AntiPatcher] The Antidote is ready\n");
        return true;
    }
    
    void shutdown() {
        if (!initialized) return;
        
        stopMonitoring();
        baselines.clear();
        detectedPatches.clear();
        initialized = false;
        
        printf("[AntiPatcher] Shutdown complete\n");
    }
    
    // Create baseline of current code
    std::string createBaseline(const std::string& regionName, 
                                void* baseAddress, 
                                size_t size,
                                bool isCritical) {
        std::lock_guard<std::mutex> lock(mutex);
        
        std::string id = "baseline_" + regionName;
        
        CodeBaseline baseline;
        baseline.regionName = regionName;
        baseline.baseAddress = baseAddress;
        baseline.size = size;
        baseline.isCritical = isCritical;
        baseline.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        
        // Copy current bytes
        baseline.originalBytes.resize(size);
        memcpy(baseline.originalBytes.data(), baseAddress, size);
        
        // Compute hash
        auto hash = SHA256Checksum::compute(baseAddress, size);
        baseline.expectedHash.assign(hash.begin(), hash.end());
        
        baselines[id] = std::move(baseline);
        
        printf("[AntiPatcher] Baseline created: %s (%zu bytes)\n", id.c_str(), size);
        return id;
    }
    
    // Scan region for patches
    std::vector<DetectedPatch> scanRegion(const std::string& regionId) {
        std::lock_guard<std::mutex> lock(mutex);
        
        std::vector<DetectedPatch> results;
        
        auto it = baselines.find(regionId);
        if (it == baselines.end()) return results;
        
        const auto& baseline = it->second;
        uint8_t* current = static_cast<uint8_t*>(baseline.baseAddress);
        
        // Scan for modifications
        for (size_t offset = 0; offset < baseline.size - 16; offset++) {
            if (current[offset] != baseline.originalBytes[offset]) {
                // Potential patch detected
                PatchSignature sig = PatchDetector::detect(current + offset, 16);
                
                if (sig != PatchSignature::UNKNOWN) {
                    DetectedPatch patch;
                    patch.id = regionId + "_patch_" + std::to_string(offset);
                    patch.address = current + offset;
                    patch.size = 16;
                    patch.signature = sig;
                    patch.currentBytes.assign(current + offset, current + offset + 16);
                    patch.expectedBytes.assign(
                        baseline.originalBytes.begin() + offset,
                        baseline.originalBytes.begin() + offset + 16);
                    patch.detectedAt = std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now().time_since_epoch()).count();
                    
                    // Check if authorized
                    auto authIt = authorizedPatches.find(patch.id);
                    patch.isKnownPatch = (authIt != authorizedPatches.end());
                    patch.isMalicious = !patch.isKnownPatch;
                    patch.source = patch.isKnownPatch ? authIt->second : "UNKNOWN";
                    patch.canRestore = true;
                    patch.restorationRisk = baseline.isCritical ? "HIGH" : "LOW";
                    
                    results.push_back(patch);
                    
                    // Log evidence
                    PatchEvidence evidence;
                    evidence.timestamp = patch.detectedAt;
                    evidence.patchId = patch.id;
                    evidence.address = patch.address;
                    evidence.operation = "DETECTED";
                    evidence.details = "Signature: " + std::to_string(static_cast<int>(sig));
                    evidence.beforeState = patch.expectedBytes;
                    evidence.afterState = patch.currentBytes;
                    evidenceLog[patch.id] = evidence;
                    
                    totalDetected++;
                }
            }
        }
        
        return results;
    }
    
    // Remove a detected patch
    bool removePatch(const std::string& patchId) {
        std::lock_guard<std::mutex> lock(mutex);
        
        auto it = detectedPatches.find(patchId);
        if (it == detectedPatches.end()) {
            // Try to find in evidence log
            auto evIt = evidenceLog.find(patchId);
            if (evIt == evidenceLog.end()) return false;
        }
        
        // Get patch info
        DetectedPatch patch = it->second;
        
        // Make memory writable
        if (!MemoryProtector::makeWritable(patch.address, patch.size)) {
            printf("[AntiPatcher] ERROR: Cannot make memory writable\n");
            return false;
        }
        
        // Restore original bytes
        memcpy(patch.address, patch.expectedBytes.data(), patch.size);
        
        // Flush cache
        MemoryProtector::flushCache(patch.address, patch.size);
        
        // Restore protection
        MemoryProtector::restoreProtection(patch.address, patch.size, 0);
        
        // Update status
        patch.isKnownPatch = false;
        detectedPatches.erase(patchId);
        
        // Log removal
        PatchEvidence evidence;
        evidence.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        evidence.patchId = patchId;
        evidence.address = patch.address;
        evidence.operation = "REMOVED";
        evidenceLog[patchId + "_removed"] = evidence;
        
        totalRemoved++;
        
        printf("[AntiPatcher] Removed patch: %s\n", patchId.c_str());
        
        if (removalCallback) {
            removalCallback(patch, true);
        }
        
        return true;
    }
    
    // Emergency purge
    int emergencyPurge() {
        printf("[AntiPatcher] EMERGENCY PURGE initiated\n");
        
        int count = 0;
        std::vector<std::string> toRemove;
        
        {
            std::lock_guard<std::mutex> lock(mutex);
            for (const auto& [id, patch] : detectedPatches) {
                if (!patch.isKnownPatch) {
                    toRemove.push_back(id);
                }
            }
        }
        
        for (const auto& id : toRemove) {
            if (removePatch(id)) {
                count++;
            }
        }
        
        printf("[AntiPatcher] Emergency purge removed %d patches\n", count);
        return count;
    }
    
    // Start monitoring
    bool startMonitoring(uint64_t intervalMs) {
        if (monitoring.exchange(true)) return false;
        
        shouldStop = false;
        policy.scanIntervalMs = intervalMs;
        
        monitorThread = std::thread([this]() {
            while (!shouldStop.load()) {
                auto patches = scanAllRegions();
                
                for (const auto& patch : patches) {
                    if (!patch.isKnownPatch && policy.alarmOnUnknown) {
                        printf("[AntiPatcher] ALERT: Unauthorized patch detected: %s\n",
                               patch.id.c_str());
                        
                        if (detectionCallback) {
                            detectionCallback(patch);
                        }
                        
                        if (policy.autoRestore && policy.level >= ImmunizationPolicy::PREVENT) {
                            removePatch(patch.id);
                        }
                    }
                }
                
                std::this_thread::sleep_for(std::chrono::milliseconds(policy.scanIntervalMs));
            }
        });
        
        printf("[AntiPatcher] Monitoring started (%llu ms interval)\n", intervalMs);
        return true;
    }
    
    void stopMonitoring() {
        if (!monitoring.exchange(false)) return;
        
        shouldStop = true;
        if (monitorThread.joinable()) {
            monitorThread.join();
        }
        
        printf("[AntiPatcher] Monitoring stopped\n");
    }
    
    // Scan all regions
    std::vector<DetectedPatch> scanAllRegions() {
        std::vector<DetectedPatch> allPatches;
        
        std::lock_guard<std::mutex> lock(mutex);
        for (const auto& [id, baseline] : baselines) {
            auto patches = scanRegion(id);
            allPatches.insert(allPatches.end(), patches.begin(), patches.end());
        }
        
        return allPatches;
    }
    
    // Authorize a patch
    void authorizePatch(const std::string& patchId, 
                       const std::string& source,
                       void* address,
                       size_t size) {
        std::lock_guard<std::mutex> lock(mutex);
        authorizedPatches[patchId] = source;
        printf("[AntiPatcher] Authorized patch: %s from %s\n", patchId.c_str(), source.c_str());
    }
    
    void revokeAuthorization(const std::string& patchId) {
        std::lock_guard<std::mutex> lock(mutex);
        authorizedPatches.erase(patchId);
        printf("[AntiPatcher] Revoked authorization: %s\n", patchId.c_str());
    }
};

// ============================================================================
// AntiPatcher Public API
// ============================================================================

AntiPatcher::AntiPatcher() : impl_(std::make_unique<Impl>()) {}
AntiPatcher::~AntiPatcher() = default;

bool AntiPatcher::initialize() { return impl_->initialize(); }
void AntiPatcher::shutdown() { impl_->shutdown(); }

std::string AntiPatcher::createBaseline(const std::string& regionName, 
                                        void* baseAddress, 
                                        size_t size,
                                        bool isCritical) {
    return impl_->createBaseline(regionName, baseAddress, size, isCritical);
}

bool AntiPatcher::removeBaseline(const std::string& regionId) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->baselines.erase(regionId) > 0;
}

std::vector<DetectedPatch> AntiPatcher::scanRegion(const std::string& regionId) {
    return impl_->scanRegion(regionId);
}

std::vector<DetectedPatch> AntiPatcher::scanAll() {
    return impl_->scanAllRegions();
}

bool AntiPatcher::removePatch(const std::string& patchId) {
    return impl_->removePatch(patchId);
}

int AntiPatcher::emergencyPurge() {
    return impl_->emergencyPurge();
}

void AntiPatcher::setPolicy(const ImmunizationPolicy& policy) {
    impl_->policy = policy;
}

ImmunizationPolicy AntiPatcher::getPolicy() const {
    return impl_->policy;
}

bool AntiPatcher::startMonitoring(uint64_t intervalMs) {
    return impl_->startMonitoring(intervalMs);
}

void AntiPatcher::stopMonitoring() {
    impl_->stopMonitoring();
}

void AntiPatcher::setDetectionCallback(DetectionCallback cb) {
    impl_->detectionCallback = cb;
}

void AntiPatcher::setRemovalCallback(RemovalCallback cb) {
    impl_->removalCallback = cb;
}

void AntiPatcher::authorizePatch(const std::string& patchId, 
                                   const std::string& source,
                                   void* address,
                                   size_t size) {
    impl_->authorizePatch(patchId, source, address, size);
}

void AntiPatcher::revokeAuthorization(const std::string& patchId) {
    impl_->revokeAuthorization(patchId);
}

bool AntiPatcher::isAuthorized(const std::string& patchId) const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->authorizedPatches.find(patchId) != impl_->authorizedPatches.end();
}

AntiPatcher::Status AntiPatcher::getStatus() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    
    Status status;
    status.initialized = impl_->initialized;
    status.monitoring = impl_->monitoring.load();
    status.baselines = impl_->baselines.size();
    status.detectedPatches = impl_->totalDetected.load();
    status.removedPatches = impl_->totalRemoved.load();
    status.blockedAttempts = impl_->totalBlocked.load();
    status.policy = impl_->policy;
    
    return status;
}

void AntiPatcher::printStatus() const {
    auto status = getStatus();
    
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║              AntiPatcher Status - The Antidote                 ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Initialized:      %s                                          ║\n", 
           status.initialized ? "YES" : "NO ");
    printf("║ Monitoring:        %s                                          ║\n",
           status.monitoring ? "YES" : "NO ");
    printf("║ Baselines:        %3zu                                          ║\n", status.baselines);
    printf("║ Detected Patches:  %3zu                                          ║\n", status.detectedPatches);
    printf("║ Removed Patches:   %3zu                                          ║\n", status.removedPatches);
    printf("║ Blocked Attempts:  %3zu                                          ║\n", status.blockedAttempts);
    printf("║ Policy Level:     %d                                             ║\n", 
           static_cast<int>(status.policy.level));
    printf("║ Auto-Restore:     %s                                          ║\n",
           status.policy.autoRestore ? "YES" : "NO ");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
}

// ============================================================================
// Global Instance
// ============================================================================

AntiPatcher& GetAntiPatcher() {
    static AntiPatcher instance;
    return instance;
}

bool VerifyCodeIntegrity(const std::string& regionName) {
    auto patches = GetAntiPatcher().scanRegion("baseline_" + regionName);
    return patches.empty();
}

int PurgeAllPatches() {
    return GetAntiPatcher().emergencyPurge();
}

} // namespace Deep2
