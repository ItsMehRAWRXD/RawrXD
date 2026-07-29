// ============================================================================
// HotPatcherSafety.hpp - Safety Enhancements for The Bottle
//
// Features:
//   - Stack canaries for patch boundaries
//   - SHA-256 checksums for patch integrity
//   - Crash recovery mechanisms
//   - Watchdog timer for patch application
//   - Memory guard pages around patches
//   - Signal handlers for crash detection
//
// The Bottle is now bulletproof.
// ============================================================================

#ifndef DEEP2_HOTPATCHER_SAFETY_HPP
#define DEEP2_HOTPATCHER_SAFETY_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <functional>
#include <atomic>
#include <mutex>

namespace Deep2 {

// ============================================================================
// Stack Canary - Detects stack corruption
// ============================================================================

class StackCanary {
public:
    static constexpr uint64_t CANARY_VALUE = 0xDEADBEEFCAFEBABEULL;
    static constexpr size_t CANARY_SIZE = 8;
    
    StackCanary();
    ~StackCanary();
    
    // Check if canary is intact
    bool isIntact() const;
    
    // Get canary location for embedding in patches
    const uint64_t* getCanaryPtr() const { return &canary_; }
    
    // Verify and report
    bool verify(const char* context);
    
private:
    uint64_t canary_;
    uint64_t guard_;  // Extra guard
};

// ============================================================================
// SHA-256 Checksum - Patch integrity verification
// ============================================================================

class SHA256Checksum {
public:
    static constexpr size_t HASH_SIZE = 32;
    using Hash = std::array<uint8_t, HASH_SIZE>;
    
    // Compute SHA-256 of data
    static Hash compute(const void* data, size_t len);
    
    // Compute SHA-256 of file
    static Hash computeFile(const std::string& path);
    
    // Convert hash to hex string
    static std::string toString(const Hash& hash);
    
    // Parse hex string to hash
    static Hash fromString(const std::string& hex);
    
    // Compare two hashes
    static bool equal(const Hash& a, const Hash& b);
    
    // Verify data against expected hash
    static bool verify(const void* data, size_t len, const Hash& expected);
};

// ============================================================================
// Memory Guard - Protect patch memory regions
// ============================================================================

class MemoryGuard {
public:
    struct GuardRegion {
        void* base;
        size_t size;
        void* preGuard;   // Guard page before
        void* postGuard;  // Guard page after
    };
    
    // Create guard pages around a memory region
    static bool guardRegion(void* base, size_t size, GuardRegion& out);
    
    // Remove guard pages
    static bool unguardRegion(const GuardRegion& region);
    
    // Check if access to region is valid
    static bool isValidAccess(const GuardRegion& region, void* addr);
    
    // Make region read-only (for patch code)
    static bool makeReadOnly(const GuardRegion& region);
    
    // Make region executable but not writable
    static bool makeExecutable(const GuardRegion& region);
};

// ============================================================================
// Watchdog Timer - Prevent hung patch operations
// ============================================================================

class PatchWatchdog {
public:
    using TimeoutCallback = std::function<void()>;
    
    PatchWatchdog();
    ~PatchWatchdog();
    
    // Start watchdog with timeout in milliseconds
    bool start(uint64_t timeoutMs, TimeoutCallback callback);
    
    // Stop watchdog
    void stop();
    
    // Reset timer (call periodically during long operations)
    void reset();
    
    // Check if watchdog is active
    bool isActive() const { return active_.load(); }
    
    // Get elapsed time
    uint64_t getElapsedMs() const;
    
private:
    std::atomic<bool> active_{false};
    std::atomic<bool> stopRequested_{false};
    std::atomic<uint64_t> startTime_{0};
    uint64_t timeoutMs_{0};
    TimeoutCallback callback_;
    std::mutex mutex_;
    
    void watchdogThread();
};

// ============================================================================
// Crash Recovery - Handle crashes during patching
// ============================================================================

class CrashRecovery {
public:
    enum class CrashType {
        UNKNOWN,
        SEGFAULT,
        ILLEGAL_INSTRUCTION,
        BUS_ERROR,
        ABORT,
        STACK_OVERFLOW
    };
    
    struct CrashContext {
        CrashType type;
        void* faultAddr;
        void* instructionPtr;
        uint64_t timestamp;
        std::string patchId;  // Which patch was active
        std::string operation; // What operation was in progress
    };
    
    using CrashHandler = std::function<void(const CrashContext&)>;
    
    // Initialize crash handlers
    static bool initialize(CrashHandler handler);
    
    // Shutdown crash handlers
    static void shutdown();
    
    // Set current operation context (for crash reporting)
    static void setContext(const std::string& patchId, const std::string& operation);
    
    // Clear context
    static void clearContext();
    
    // Get last crash info
    static CrashContext getLastCrash();
    
    // Check if recovering from crash
    static bool isRecovering();
    
    // Signal handlers (platform-specific)
    static void handleSignal(int sig, void* info, void* context);
    
    // Accessors for internal signal handlers (platform-specific handlers need these)
    static CrashContext& accessCurrentContext() { return currentContext_; }
    static CrashContext& accessLastCrash() { return lastCrash_; }
    static std::mutex& accessCrashMutex() { return crashMutex_; }
    static CrashHandler& accessUserHandler() { return userHandler_; }
    
private:
    static CrashHandler userHandler_;
    static std::atomic<bool> initialized_;
    static thread_local CrashContext currentContext_;
    static CrashContext lastCrash_;
    static std::mutex crashMutex_;
};

// ============================================================================
// Patch Safety Monitor - Continuous monitoring
// ============================================================================

class PatchSafetyMonitor {
public:
    struct SafetyReport {
        bool allCanariesIntact;
        bool allChecksumsValid;
        bool noMemoryViolations;
        bool watchdogHealthy;
        uint64_t lastCheckTime;
        std::vector<std::string> violations;
    };
    
    PatchSafetyMonitor();
    ~PatchSafetyMonitor();
    
    // Start monitoring
    bool start(uint64_t checkIntervalMs = 1000);
    
    // Stop monitoring
    void stop();
    
    // Register a patch for monitoring
    void registerPatch(const std::string& patchId, void* codeBase, size_t codeSize);
    
    // Unregister a patch
    void unregisterPatch(const std::string& patchId);
    
    // Manual safety check
    SafetyReport checkSafety();

    // Get last report
    SafetyReport getLastReport() const;

    // Set violation handler
    using ViolationHandler = std::function<void(const SafetyReport&)>;
    void setViolationHandler(ViolationHandler handler);

    // Static accessor for global monitor instance
    static PatchSafetyMonitor& instance();

    // Check if watchdog is in panic state
    static bool isWatchdogPanicked();

private:
    std::atomic<bool> running_{false};
    uint64_t checkIntervalMs_{1000};
    
    struct MonitoredPatch {
        std::string patchId;
        void* codeBase;
        size_t codeSize;
        SHA256Checksum::Hash expectedHash;
        StackCanary canary;
        MemoryGuard::GuardRegion guard;
    };
    
    std::unordered_map<std::string, MonitoredPatch> monitoredPatches_;
    mutable std::mutex patchesMutex_;
    SafetyReport lastReport_;
    mutable std::mutex reportMutex_;
    ViolationHandler violationHandler_;
    
    void monitorThread();
    bool verifyPatch(const MonitoredPatch& patch);
};

// ============================================================================
// Safety Utilities
// ============================================================================

class PatchSafety {
public:
    // Combined safety check before applying patch
    struct PreFlightCheck {
        bool memoryAvailable = true;
        bool stackSpaceAvailable = true;
        bool noActiveWatchdog = true;
        bool checksumValid = true;
        bool dependenciesSafe = true;
        bool noConflicts = true;
        float riskScore = 0.0f;
        std::vector<std::string> warnings;
        std::vector<std::string> blockers;
    };
    
    static PreFlightCheck runPreFlight(const std::string& patchId);
    
    // Calculate risk score (0-1)
    static float calculateRiskScore(const std::string& patchId);
    
    // Estimate rollback time
    static uint64_t estimateRollbackTimeMs(const std::string& patchId);
    
    // Verify system can handle patch
    static bool verifySystemHealth();
    
    // Get safety recommendations
    static std::vector<std::string> getRecommendations(const std::string& patchId);
};

// ============================================================================
// Integration Helpers
// ============================================================================

// RAII guard for patch operations
class PatchOperationGuard {
public:
    PatchOperationGuard(const std::string& patchId, const std::string& operation);
    ~PatchOperationGuard();
    
    // Mark operation as successful (prevents rollback on destruction)
    void markSuccess();
    
    // Check if operation is still valid
    bool isValid() const { return valid_; }
    
private:
    std::string patchId_;
    std::string operation_;
    bool valid_{true};
    bool success_{false};
    StackCanary canary_;
};

// Scoped watchdog for operations
class ScopedWatchdog {
public:
    ScopedWatchdog(uint64_t timeoutMs, PatchWatchdog::TimeoutCallback callback);
    ~ScopedWatchdog();
    
    void reset();
    
private:
    PatchWatchdog watchdog_;
};

} // namespace Deep2

#endif // DEEP2_HOTPATCHER_SAFETY_HPP
