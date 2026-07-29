// ============================================================================
// HotPatcher.hpp - Runtime Code Modification System for Deep2Engine
//
// The "Bottle" - Live patching without recompilation or restart
//
// Features:
//   - Function hooking/replacement at runtime
//   - Patch versioning and rollback
//   - A/B testing different implementations
//   - Performance monitoring per patch
//   - Safety validation (checksums, stack guards)
//   - Atomic patch application (all-or-nothing)
//
// Architecture:
//   Patch Registry → Validator → Applier → Monitor
//      ↑                ↓          ↓         ↓
//   Patch Queue    Safety      Atomic    Metrics
//
// Copyright (c) 2026 RawrXD Sovereign Runtime - The Bottle
// ============================================================================

#ifndef DEEP2_HOTPATCHER_HPP
#define DEEP2_HOTPATCHER_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>

namespace Deep2 {

// ============================================================================
// Patch Types
// ============================================================================

enum class PatchType {
    FUNCTION_HOOK,      // Replace function implementation
    VTABLE_OVERRIDE,    // Override virtual function table entry
    BINARY_PATCH,       // Raw binary modification (dangerous)
    CONFIG_OVERRIDE,    // Runtime config change
    KERNEL_REPLACE,     // Replace compute kernel (GEMM, attention, etc.)
    SAMPLER_SWAP,       // Swap sampling algorithm
    DECODER_MODE,       // Switch between greedy/beam/Medusa
    LAYER_INJECTION     // Inject new layer or bypass existing
};

enum class PatchStatus {
    PENDING,            // Queued for validation
    VALIDATING,         // Safety checks in progress
    READY,              // Validated, ready to apply
    APPLYING,           // Currently being applied
    ACTIVE,             // Successfully applied and running
    FAILED,             // Validation or application failed
    ROLLED_BACK,        // Was active, now reverted
    DISABLED            // Manually disabled
};

// ============================================================================
// Patch Metadata
// ============================================================================

struct PatchMetadata {
    std::string id;                    // Unique patch ID (UUID)
    std::string name;                  // Human-readable name
    std::string description;           // What this patch does
    std::string author;                // Who created it
    std::string version;               // Semantic version
    std::string targetVersion;         // Engine version this patches
    PatchType type;                    // Type of patch
    
    uint64_t createdAt;                // Timestamp
    uint64_t appliedAt;                // When applied
    uint64_t durationMs;               // How long application took
    
    // Safety
    std::string checksum;              // SHA-256 of patch data
    std::vector<std::string> dependencies; // Required patches
    std::vector<std::string> conflicts;    // Incompatible patches
    
    // Rollback
    bool canRollback;                  // Can we undo this?
    std::string rollbackData;          // Data needed to restore
    
    // Performance
    float expectedSpeedup;             // Expected performance gain
    float maxMemoryOverhead;             // Max additional memory
};

// ============================================================================
// Function Hook Patch
// ============================================================================

template<typename FuncType>
struct FunctionHook {
    std::string targetName;            // Name of function to hook
    FuncType* originalFunc;              // Pointer to original
    FuncType* replacementFunc;           // Pointer to replacement
    FuncType* trampoline;              // Gateway to call original
    
    // For x64: 12 bytes (mov rax, addr; jmp rax)
    // For ARM64: 16 bytes (ldr x16, addr; br x16)
    uint8_t originalBytes[16];           // Original bytes saved
    uint8_t patchBytes[16];              // Patch bytes to write
    size_t patchSize;                    // Size of patch
};

// ============================================================================
// Kernel Replacement Patch (for compute kernels)
// ============================================================================

struct KernelReplacement {
    std::string kernelName;              // e.g., "attention", "gemm", "rope"
    std::string variant;               // e.g., "avx512", "neon", "cuda"
    void* oldKernelPtr;                // Original kernel function
    void* newKernelPtr;                // Replacement kernel function
    void** vtableSlot;                 // For virtual kernel dispatch
    
    // Performance characteristics
    size_t optimalBatchSize;
    size_t optimalSeqLen;
    bool requiresAlignedMemory;
};

// ============================================================================
// Decoder Mode Patch (switch between decoding strategies)
// ============================================================================

struct DecoderModePatch {
    enum class Mode {
        STANDARD,           // Autoregressive 1 token/step
        GREEDY_MEDUSA,        // Our corrected greedy Medusa
        GENERAL_MEDUSA,       // Full tree Medusa
        BEAM_SEARCH,          // Beam search
        SPECULATIVE_DRAFT     // Draft-then-verify
    };
    
    struct Config {
        size_t numHeads;
        size_t maxTreeSize;
        float temperature;
        bool useReverseAccept;
        bool useRNG;
    };
    
    Mode targetMode;
    Config config;
    
    // Transition
    bool allowInFlightTokens;  // Can we switch mid-generation?
    size_t switchPoint;        // Switch after N tokens
};

// ============================================================================
// Patch Validation Result
// ============================================================================

struct ValidationResult {
    bool passed;
    std::vector<std::string> warnings;
    std::vector<std::string> errors;
    
    // Safety checks
    bool checksumValid;
    bool dependenciesMet;
    bool noConflicts;
    bool memoryAvailable;
    bool stackGuardIntact;
    
    // Performance prediction
    float predictedSpeedup;
    float predictedMemoryOverhead;
    float riskScore;  // 0-1, higher = riskier
};

// ============================================================================
// Performance Metrics for Active Patches
// ============================================================================

struct PatchMetrics {
    std::string patchId;
    
    // Timing
    uint64_t calls;
    uint64_t totalTimeNs;
    uint64_t minTimeNs;
    uint64_t maxTimeNs;
    double avgTimeNs;
    
    // Comparison vs original
    double speedupRatio;
    double latencyReduction;
    
    // Memory
    size_t peakMemoryBytes;
    size_t currentMemoryBytes;
    
    // Errors
    uint64_t errors;
    uint64_t rollbacks;
    
    // Last updated
    uint64_t lastUpdateMs;
};

// ============================================================================
// HotPatcher - The Bottle
// ============================================================================

class HotPatcher {
public:
    HotPatcher();
    ~HotPatcher();
    
    // Initialize the patcher (set up trampolines, etc.)
    bool initialize();
    
    // Shutdown and cleanup
    void shutdown();
    
    // =========================================================================
    // Patch Registration
    // =========================================================================
    
    // Register a function hook patch
    template<typename FuncType>
    std::string registerFunctionHook(
        const std::string& name,
        FuncType* targetFunc,
        FuncType* replacementFunc,
        const PatchMetadata& meta);
    
    // Register a kernel replacement
    std::string registerKernelReplacement(
        const KernelReplacement& kernel,
        const PatchMetadata& meta);
    
    // Register a decoder mode switch
    std::string registerDecoderMode(
        const DecoderModePatch& mode,
        const PatchMetadata& meta);
    
    // Register a config override
    std::string registerConfigOverride(
        const std::string& configPath,
        const std::string& newValue,
        const PatchMetadata& meta);
    
    // =========================================================================
    // Patch Lifecycle
    // =========================================================================
    
    // Validate a patch before applying
    ValidationResult validate(const std::string& patchId);
    
    // Apply a patch (atomic - all or nothing)
    bool apply(const std::string& patchId);
    
    // Apply multiple patches atomically
    bool applyBatch(const std::vector<std::string>& patchIds);
    
    // Rollback a patch
    bool rollback(const std::string& patchId);
    
    // Disable a patch (temporarily)
    bool disable(const std::string& patchId);
    
    // Re-enable a disabled patch
    bool enable(const std::string& patchId);
    
    // =========================================================================
    // Query & Monitoring
    // =========================================================================
    
    // Get patch status
    PatchStatus getStatus(const std::string& patchId);
    
    // Get patch metadata
    PatchMetadata getMetadata(const std::string& patchId);
    
    // Get metrics for an active patch
    PatchMetrics getMetrics(const std::string& patchId);
    
    // List all patches
    std::vector<std::string> listPatches(PatchStatus filter = PatchStatus::ACTIVE);
    
    // List patches by type
    std::vector<std::string> listPatchesByType(PatchType type);
    
    // Check if a patch is active
    bool isActive(const std::string& patchId);
    
    // Get currently active kernel for a name
    std::string getActiveKernel(const std::string& kernelName);
    
    // =========================================================================
    // A/B Testing
    // =========================================================================
    
    // Start A/B test between two patches
    std::string startABTest(
        const std::string& patchA,
        const std::string& patchB,
        double trafficSplit = 0.5);  // 0.5 = 50/50
    
    // End A/B test and select winner
    bool endABTest(const std::string& testId, bool selectA);
    
    // Get A/B test results
    struct ABTestResult {
        std::string testId;
        uint64_t callsA, callsB;
        double avgLatencyA, avgLatencyB;
        double errorRateA, errorRateB;
        std::string winner;
    };
    ABTestResult getABTestResult(const std::string& testId);
    
    // =========================================================================
    // Safety & Recovery
    // =========================================================================
    
    // Enable/disable automatic rollback on error
    void setAutoRollback(bool enabled);
    bool isAutoRollbackEnabled() const;
    
    // Set maximum patch application time
    void setMaxApplyTimeMs(uint64_t ms);
    
    // Emergency rollback all patches
    bool emergencyRollback();
    
    // Verify system integrity
    bool verifyIntegrity();

    // Check if patch system is in error state
    bool isInErrorState() const;

    // Create restore point
    std::string createRestorePoint(const std::string& description);
    
    // Restore to point
    bool restoreToPoint(const std::string& pointId);
    
    // =========================================================================
    // Statistics & Export
    // =========================================================================
    
    // Export patch report
    std::string exportReport();
    
    // Get summary statistics
    struct SummaryStats {
        size_t totalPatches;
        size_t activePatches;
        size_t failedPatches;
        size_t rolledBackPatches;
        double avgSpeedup;
        double totalMemoryOverhead;
        uint64_t totalPatchTimeMs;
    };
    SummaryStats getSummaryStats();
    
    // Print status to console
    void printStatus();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
    
    // Internal helpers
    bool validateChecksum(const std::string& patchId);
    bool checkDependencies(const std::string& patchId);
    bool checkConflicts(const std::string& patchId);
    bool verifyMemorySafety(const std::string& patchId);
    
    // Platform-specific
    bool writeMemory(void* addr, const void* data, size_t len);
    bool protectMemory(void* addr, size_t len, int prot);
    void* allocateTrampoline(size_t size);
    void flushInstructionCache(void* addr, size_t len);
};

// ============================================================================
// Convenience Macros for Patch Registration
// ============================================================================

#define HOTPATCH_REGISTER_FUNC(patcher, name, target, replacement) \
    patcher.registerFunctionHook(name, target, replacement, \
        Deep2::PatchMetadata{name, "Auto-registered function hook", "system", "1.0.0", "", Deep2::PatchType::FUNCTION_HOOK})

#define HOTPATCH_REGISTER_KERNEL(patcher, name, variant, oldPtr, newPtr) \
    patcher.registerKernelReplacement( \
        Deep2::KernelReplacement{name, variant, oldPtr, newPtr, nullptr, 1, 1, false}, \
        Deep2::PatchMetadata{name, "Kernel replacement: " + variant, "system", "1.0.0", "", Deep2::PatchType::KERNEL_REPLACE})

// ============================================================================
// Global HotPatcher Instance (singleton)
// ============================================================================

HotPatcher& GetHotPatcher();

} // namespace Deep2

#endif // DEEP2_HOTPATCHER_HPP
