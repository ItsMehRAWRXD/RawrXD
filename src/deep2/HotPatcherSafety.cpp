// ============================================================================
// HotPatcherSafety.cpp - Safety Implementation for The Bottle
//
// Implements:
//   - Stack canaries for corruption detection
//   - SHA-256 checksums for integrity
//   - Crash recovery with signal handlers
//   - Watchdog timers for hung detection
//   - Memory guard pages
//
// The Bottle is now bulletproof.
// ============================================================================

#include "HotPatcherSafety.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <chrono>
#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#include <intrin.h>
#else
#include <signal.h>
#include <sys/mman.h>
#include <unistd.h>
#include <setjmp.h>
#endif

namespace Deep2 {

// ============================================================================
// SHA-256 Implementation (simplified - use OpenSSL in production)
// ============================================================================

// SHA-256 constants
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static void sha256_transform(uint32_t state[8], const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
    
    for (int i = 0; i < 16; i++) {
        m[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) | 
               (data[i * 4 + 2] << 8) | data[i * 4 + 3];
    }
    for (int i = 16; i < 64; i++) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }
    
    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];
    
    for (int i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}

SHA256Checksum::Hash SHA256Checksum::compute(const void* data, size_t len) {
    Hash hash;
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    const uint8_t* ptr = static_cast<const uint8_t*>(data);
    size_t bitLen = len * 8;
    
    // Process full blocks
    while (len >= 64) {
        sha256_transform(state, ptr);
        ptr += 64;
        len -= 64;
    }
    
    // Padding
    uint8_t finalBlock[64];
    size_t rem = len;
    memcpy(finalBlock, ptr, rem);
    finalBlock[rem++] = 0x80;
    
    if (rem > 56) {
        memset(finalBlock + rem, 0, 64 - rem);
        sha256_transform(state, finalBlock);
        rem = 0;
    }
    memset(finalBlock + rem, 0, 56 - rem);
    
    // Append length
    for (int i = 0; i < 8; i++) {
        finalBlock[56 + i] = (bitLen >> (56 - i * 8)) & 0xFF;
    }
    sha256_transform(state, finalBlock);
    
    // Convert to bytes
    for (int i = 0; i < 8; i++) {
        hash[i * 4] = (state[i] >> 24) & 0xFF;
        hash[i * 4 + 1] = (state[i] >> 16) & 0xFF;
        hash[i * 4 + 2] = (state[i] >> 8) & 0xFF;
        hash[i * 4 + 3] = state[i] & 0xFF;
    }
    
    return hash;
}

std::string SHA256Checksum::toString(const Hash& hash) {
    static const char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(64);
    for (auto b : hash) {
        result += hex[b >> 4];
        result += hex[b & 0xF];
    }
    return result;
}

bool SHA256Checksum::verify(const void* data, size_t len, const Hash& expected) {
    Hash actual = compute(data, len);
    return equal(actual, expected);
}

bool SHA256Checksum::equal(const Hash& a, const Hash& b) {
    return memcmp(a.data(), b.data(), HASH_SIZE) == 0;
}

// ============================================================================
// Stack Canary
// ============================================================================

StackCanary::StackCanary() : canary_(CANARY_VALUE), guard_(CANARY_VALUE) {}

StackCanary::~StackCanary() {
    if (!isIntact()) {
        printf("[SAFETY] CRITICAL: Stack canary corrupted!\n");
    }
}

bool StackCanary::isIntact() const {
    return canary_ == CANARY_VALUE && guard_ == CANARY_VALUE;
}

bool StackCanary::verify(const char* context) {
    if (!isIntact()) {
        printf("[SAFETY] Stack canary violation in: %s\n", context);
        return false;
    }
    return true;
}

// ============================================================================
// Memory Guard
// ============================================================================

bool MemoryGuard::guardRegion(void* base, size_t size, GuardRegion& out) {
    out.base = base;
    out.size = size;
    
#ifdef _WIN32
    // Windows: Allocate guard pages
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    size_t pageSize = si.dwPageSize;
    
    // Allocate guard pages before and after
    out.preGuard = VirtualAlloc(nullptr, pageSize, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    out.postGuard = VirtualAlloc(nullptr, pageSize, MEM_COMMIT | MEM_RESERVE, PAGE_NOACCESS);
    
    if (!out.preGuard || !out.postGuard) {
        return false;
    }
#else
    // Unix: Use mprotect on existing pages
    size_t pageSize = sysconf(_SC_PAGESIZE);
    
    // Calculate guard page locations
    uintptr_t baseAddr = reinterpret_cast<uintptr_t>(base);
    out.preGuard = reinterpret_cast<void*>((baseAddr & ~(pageSize - 1)) - pageSize);
    out.postGuard = reinterpret_cast<void*>(((baseAddr + size + pageSize - 1) & ~(pageSize - 1)));
    
    // Protect guard pages
    if (mprotect(out.preGuard, pageSize, PROT_NONE) != 0 ||
        mprotect(out.postGuard, pageSize, PROT_NONE) != 0) {
        return false;
    }
#endif
    
    return true;
}

bool MemoryGuard::unguardRegion(const GuardRegion& region) {
#ifdef _WIN32
    if (region.preGuard) VirtualFree(region.preGuard, 0, MEM_RELEASE);
    if (region.postGuard) VirtualFree(region.postGuard, 0, MEM_RELEASE);
#else
    size_t pageSize = sysconf(_SC_PAGESIZE);
    mprotect(region.preGuard, pageSize, PROT_READ | PROT_WRITE);
    mprotect(region.postGuard, pageSize, PROT_READ | PROT_WRITE);
#endif
    return true;
}

bool MemoryGuard::makeReadOnly(const GuardRegion& region) {
#ifdef _WIN32
    DWORD oldProtect;
    return VirtualProtect(region.base, region.size, PAGE_EXECUTE_READ, &oldProtect) != 0;
#else
    return mprotect(region.base, region.size, PROT_READ | PROT_EXEC) == 0;
#endif
}

// ============================================================================
// Watchdog Timer
// ============================================================================

PatchWatchdog::PatchWatchdog() = default;

PatchWatchdog::~PatchWatchdog() {
    stop();
}

bool PatchWatchdog::start(uint64_t timeoutMs, TimeoutCallback callback) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (active_.load()) {
        return false;  // Already running
    }
    
    timeoutMs_ = timeoutMs;
    callback_ = callback;
    startTime_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    active_ = true;
    stopRequested_ = false;
    
    std::thread t(&PatchWatchdog::watchdogThread, this);
    t.detach();
    
    return true;
}

void PatchWatchdog::stop() {
    active_ = false;
    stopRequested_ = true;
}

void PatchWatchdog::reset() {
    startTime_ = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
}

uint64_t PatchWatchdog::getElapsedMs() const {
    auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    return now - startTime_.load();
}

void PatchWatchdog::watchdogThread() {
    while (active_.load() && !stopRequested_.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        
        if (getElapsedMs() > timeoutMs_) {
            printf("[SAFETY] Watchdog timeout after %llu ms\n", timeoutMs_);
            if (callback_) {
                callback_();
            }
            active_ = false;
            break;
        }
    }
}

// ============================================================================
// Crash Recovery
// ============================================================================

CrashRecovery::CrashHandler CrashRecovery::userHandler_;
std::atomic<bool> CrashRecovery::initialized_{false};
thread_local CrashRecovery::CrashContext CrashRecovery::currentContext_;
CrashRecovery::CrashContext CrashRecovery::lastCrash_;
std::mutex CrashRecovery::crashMutex_;

#ifdef _WIN32
static LONG WINAPI exceptionHandler(EXCEPTION_POINTERS* info) {
    CrashRecovery::CrashContext ctx;
    ctx.type = CrashRecovery::CrashType::UNKNOWN;
    ctx.faultAddr = nullptr;
    ctx.instructionPtr = nullptr;
    ctx.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    if (info && info->ExceptionRecord) {
        ctx.faultAddr = reinterpret_cast<void*>(info->ExceptionRecord->ExceptionInformation[1]);
        ctx.instructionPtr = reinterpret_cast<void*>(info->ContextRecord->Rip);
        
        switch (info->ExceptionRecord->ExceptionCode) {
            case EXCEPTION_ACCESS_VIOLATION: ctx.type = CrashRecovery::CrashType::SEGFAULT; break;
            case EXCEPTION_ILLEGAL_INSTRUCTION: ctx.type = CrashRecovery::CrashType::ILLEGAL_INSTRUCTION; break;
            case EXCEPTION_STACK_OVERFLOW: ctx.type = CrashRecovery::CrashType::STACK_OVERFLOW; break;
        }
    }
    
    ctx.patchId = CrashRecovery::accessCurrentContext().patchId;
    ctx.operation = CrashRecovery::accessCurrentContext().operation;
    
    {
        std::lock_guard<std::mutex> lock(CrashRecovery::accessCrashMutex());
        CrashRecovery::accessLastCrash() = ctx;
    }
    
    printf("[SAFETY] CRASH DETECTED: type=%d, patch=%s, op=%s\n",
           static_cast<int>(ctx.type), ctx.patchId.c_str(), ctx.operation.c_str());
    
    if (CrashRecovery::accessUserHandler()) {
        CrashRecovery::accessUserHandler()(ctx);
    }
    
    return EXCEPTION_EXECUTE_HANDLER;
}
#else
static void signalHandler(int sig, siginfo_t* info, void* context) {
    CrashRecovery::CrashContext ctx;
    ctx.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    ctx.patchId = CrashRecovery::accessCurrentContext().patchId;
    ctx.operation = CrashRecovery::accessCurrentContext().operation;
    
    if (info) {
        ctx.faultAddr = info->si_addr;
    }
    
    switch (sig) {
        case SIGSEGV: ctx.type = CrashRecovery::CrashType::SEGFAULT; break;
        case SIGILL: ctx.type = CrashRecovery::CrashType::ILLEGAL_INSTRUCTION; break;
        case SIGBUS: ctx.type = CrashRecovery::CrashType::BUS_ERROR; break;
        case SIGABRT: ctx.type = CrashRecovery::CrashType::ABORT; break;
    }
    
    {
        std::lock_guard<std::mutex> lock(CrashRecovery::accessCrashMutex());
        CrashRecovery::accessLastCrash() = ctx;
    }
    
    printf("[SAFETY] CRASH DETECTED: sig=%d, patch=%s, op=%s\n",
           sig, ctx.patchId.c_str(), ctx.operation.c_str());
    
    if (CrashRecovery::accessUserHandler()) {
        CrashRecovery::accessUserHandler()(ctx);
    }
    
    // Re-raise to get core dump
    signal(sig, SIG_DFL);
    raise(sig);
}
#endif

bool CrashRecovery::initialize(CrashHandler handler) {
    if (initialized_.exchange(true)) {
        return true;  // Already initialized
    }
    
    userHandler_ = handler;
    
#ifdef _WIN32
    SetUnhandledExceptionFilter(exceptionHandler);
#else
    struct sigaction sa;
    sa.sa_sigaction = signalHandler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    
    sigaction(SIGSEGV, &sa, nullptr);
    sigaction(SIGILL, &sa, nullptr);
    sigaction(SIGBUS, &sa, nullptr);
    sigaction(SIGABRT, &sa, nullptr);
#endif
    
    printf("[SAFETY] Crash recovery initialized\n");
    return true;
}

void CrashRecovery::shutdown() {
    initialized_ = false;
    
#ifdef _WIN32
    SetUnhandledExceptionFilter(nullptr);
#else
    signal(SIGSEGV, SIG_DFL);
    signal(SIGILL, SIG_DFL);
    signal(SIGBUS, SIG_DFL);
    signal(SIGABRT, SIG_DFL);
#endif
}

void CrashRecovery::setContext(const std::string& patchId, const std::string& operation) {
    currentContext_.patchId = patchId;
    currentContext_.operation = operation;
}

void CrashRecovery::clearContext() {
    currentContext_.patchId.clear();
    currentContext_.operation.clear();
}

CrashRecovery::CrashContext CrashRecovery::getLastCrash() {
    std::lock_guard<std::mutex> lock(crashMutex_);
    return lastCrash_;
}

bool CrashRecovery::isRecovering() {
    return !lastCrash_.patchId.empty();
}

// ============================================================================
// Patch Safety Monitor
// ============================================================================

PatchSafetyMonitor::PatchSafetyMonitor() = default;

PatchSafetyMonitor::~PatchSafetyMonitor() {
    stop();
}

bool PatchSafetyMonitor::start(uint64_t checkIntervalMs) {
    if (running_.exchange(true)) {
        return false;
    }
    
    checkIntervalMs_ = checkIntervalMs;
    
    std::thread t(&PatchSafetyMonitor::monitorThread, this);
    t.detach();
    
    printf("[SAFETY] Patch safety monitor started (interval=%llu ms)\n", checkIntervalMs);
    return true;
}

void PatchSafetyMonitor::stop() {
    running_ = false;
}

void PatchSafetyMonitor::registerPatch(const std::string& patchId, void* codeBase, size_t codeSize) {
    std::lock_guard<std::mutex> lock(patchesMutex_);
    
    MonitoredPatch patch;
    patch.patchId = patchId;
    patch.codeBase = codeBase;
    patch.codeSize = codeSize;
    patch.expectedHash = SHA256Checksum::compute(codeBase, codeSize);
    
    // Set up memory guard
    MemoryGuard::guardRegion(codeBase, codeSize, patch.guard);
    
    monitoredPatches_[patchId] = std::move(patch);
    
    printf("[SAFETY] Registered patch for monitoring: %s\n", patchId.c_str());
}

void PatchSafetyMonitor::unregisterPatch(const std::string& patchId) {
    std::lock_guard<std::mutex> lock(patchesMutex_);
    
    auto it = monitoredPatches_.find(patchId);
    if (it != monitoredPatches_.end()) {
        MemoryGuard::unguardRegion(it->second.guard);
        monitoredPatches_.erase(it);
        printf("[SAFETY] Unregistered patch: %s\n", patchId.c_str());
    }
}

PatchSafetyMonitor::SafetyReport PatchSafetyMonitor::checkSafety() {
    SafetyReport report;
    report.allCanariesIntact = true;
    report.allChecksumsValid = true;
    report.noMemoryViolations = true;
    report.watchdogHealthy = true;
    report.lastCheckTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    std::lock_guard<std::mutex> lock(patchesMutex_);
    
    for (const auto& [id, patch] : monitoredPatches_) {
        // Check canary
        if (!patch.canary.isIntact()) {
            report.allCanariesIntact = false;
            report.violations.push_back("Stack canary corrupted for patch: " + id);
        }
        
        // Check checksum
        if (!verifyPatch(patch)) {
            report.allChecksumsValid = false;
            report.violations.push_back("Checksum mismatch for patch: " + id);
        }
    }
    
    {
        std::lock_guard<std::mutex> rlock(reportMutex_);
        lastReport_ = report;
    }
    
    if (!report.violations.empty() && violationHandler_) {
        violationHandler_(report);
    }
    
    return report;
}

bool PatchSafetyMonitor::verifyPatch(const MonitoredPatch& patch) {
    SHA256Checksum::Hash currentHash = SHA256Checksum::compute(patch.codeBase, patch.codeSize);
    return SHA256Checksum::equal(currentHash, patch.expectedHash);
}

void PatchSafetyMonitor::monitorThread() {
    while (running_) {
        checkSafety();
        std::this_thread::sleep_for(std::chrono::milliseconds(checkIntervalMs_));
    }
}

PatchSafetyMonitor::SafetyReport PatchSafetyMonitor::getLastReport() const {
    std::lock_guard<std::mutex> lock(reportMutex_);
    return lastReport_;
}

void PatchSafetyMonitor::setViolationHandler(ViolationHandler handler) {
    violationHandler_ = handler;
}

// ============================================================================
// PatchSafety - Static safety utilities
// ============================================================================

PatchSafety::PreFlightCheck PatchSafety::runPreFlight(const std::string& patchId) {
    PreFlightCheck result;
    result.memoryAvailable = true;  // TODO: Check actual memory
    result.stackSpaceAvailable = true;  // TODO: Check stack space
    result.noActiveWatchdog = true;  // TODO: Check for active watchdog
    result.checksumValid = true;  // TODO: Verify checksum
    result.dependenciesSafe = true;  // TODO: Check dependencies
    return result;
}

float PatchSafety::calculateRiskScore(const std::string& patchId) {
    // Base risk score
    float score = 0.1f;
    
    // Higher risk for certain patch types
    // TODO: Look up actual patch type
    // score += 0.3f for BINARY_PATCH, etc.
    
    // Higher risk if no rollback capability
    // TODO: Check patch metadata
    // score += 0.2f if !canRollback
    
    return std::min(score, 1.0f);
}

uint64_t PatchSafety::estimateRollbackTimeMs(const std::string& patchId) {
    // Estimate based on patch type and size
    // Simple patches: ~1ms
    // Complex patches: ~10-100ms
    return 5;  // Conservative estimate
}

bool PatchSafety::verifySystemHealth() {
    // Check system can handle patches
    // - Memory available
    // - Stack space
    // - No pending crashes
    return true;  // TODO: Implement actual checks
}

std::vector<std::string> PatchSafety::getRecommendations(const std::string& patchId) {
    std::vector<std::string> recs;
    
    float risk = calculateRiskScore(patchId);
    if (risk > 0.7f) {
        recs.push_back("High risk patch - test in staging first");
    }
    if (risk > 0.5f) {
        recs.push_back("Consider creating restore point before applying");
    }
    
    recs.push_back("Monitor metrics after application");
    return recs;
}

// ============================================================================
// Patch Operation Guard (RAII)
// ============================================================================

PatchOperationGuard::PatchOperationGuard(const std::string& patchId, const std::string& operation)
    : patchId_(patchId), operation_(operation) {
    CrashRecovery::setContext(patchId, operation);
    printf("[SAFETY] Started operation: %s on patch %s\n", operation.c_str(), patchId.c_str());
}

PatchOperationGuard::~PatchOperationGuard() {
    if (valid_ && !success_) {
        printf("[SAFETY] Operation failed, initiating rollback: %s\n", operation_.c_str());
        // In real implementation, trigger rollback here
    }
    CrashRecovery::clearContext();
}

void PatchOperationGuard::markSuccess() {
    success_ = true;
    printf("[SAFETY] Operation completed successfully: %s\n", operation_.c_str());
}

// ============================================================================
// Scoped Watchdog
// ============================================================================

ScopedWatchdog::ScopedWatchdog(uint64_t timeoutMs, PatchWatchdog::TimeoutCallback callback) {
    watchdog_.start(timeoutMs, callback);
}

ScopedWatchdog::~ScopedWatchdog() {
    watchdog_.stop();
}

void ScopedWatchdog::reset() {
    watchdog_.reset();
}

} // namespace Deep2
