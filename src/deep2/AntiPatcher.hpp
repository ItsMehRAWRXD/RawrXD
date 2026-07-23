// ============================================================================
// AntiPatcher.hpp - The Antidote to The Bottle
//
// While The Bottle injects life (patches), The Antidote detects and removes
// unauthorized modifications, restores original code, and maintains integrity.
//
// Features:
//   - Patch detection (find injected code, hooks, trampolines)
//   - Code integrity verification (baseline vs current)
//   - Automatic restoration of original code
//   - Immunization (prevent future patching)
//   - Forensic analysis (who patched what when)
//
// The Antidote is the yin to The Bottle's yang.
//
// Copyright (c) 2026 RawrXD Sovereign Runtime - The Antidote
// ============================================================================

#ifndef DEEP2_ANTIPATCHER_HPP
#define DEEP2_ANTIPATCHER_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <memory>
#include <mutex>
#include <chrono>

namespace Deep2 {

// ============================================================================
// Detection Signatures
// ============================================================================

enum class PatchSignature {
    UNKNOWN,
    X64_JMP_ABSOLUTE,      // mov rax, addr; jmp rax (12 bytes)
    X64_JMP_RELATIVE,      // jmp rel32 (5 bytes)
    X64_CALL_ABSOLUTE,     // call absolute
    X64_TRAMPOLINE,        // Trampoline pattern
    VTABLE_HOOK,           // Virtual table modification
    IAT_HOOK,              // Import Address Table hook
    INLINE_HOOK,           // Short jump to trampoline
    HOTPATCH_NOP,          // Microsoft hotpatch NOP padding
    DETOUR_PATCH,          // Microsoft Detours style
    UNKNOWN_HOOK           // Unrecognized but suspicious
};

// ============================================================================
// Code Region Baseline
// ============================================================================

struct CodeBaseline {
    std::string regionName;
    void* baseAddress;
    size_t size;
    std::vector<uint8_t> originalBytes;
    std::vector<uint8_t> expectedHash;  // SHA-256
    uint64_t timestamp;
    bool isCritical;  // Cannot be patched without alarm
    
    // For verification
    bool verifyIntegrity() const;
    bool isModified() const;
};

// ============================================================================
// Detected Patch
// ============================================================================

struct DetectedPatch {
    std::string id;
    void* address;
    size_t size;
    PatchSignature signature;
    std::vector<uint8_t> currentBytes;
    std::vector<uint8_t> expectedBytes;
    
    // Analysis
    bool isKnownPatch;      // From our registry
    bool isMalicious;       // Unknown origin
    std::string source;     // If known
    uint64_t detectedAt;
    
    // Restoration
    bool canRestore;
    std::string restorationRisk;  // LOW, MEDIUM, HIGH
};

// ============================================================================
// Forensic Evidence
// ============================================================================

struct PatchEvidence {
    uint64_t timestamp;
    std::string patchId;
    void* address;
    std::string operation;  // DETECTED, REMOVED, BLOCKED
    std::string details;
    std::vector<uint8_t> beforeState;
    std::vector<uint8_t> afterState;
    std::string callStack;  // When available
};

// ============================================================================
// Immunization Policy
// ============================================================================

struct ImmunizationPolicy {
    enum Level {
        NONE,           // No protection
        MONITOR,        // Detect only, log
        PREVENT,        // Block unauthorized patches
        AGGRESSIVE      // Block all patches, alarm on attempt
    };
    
    Level level = MONITOR;
    bool autoRestore = false;      // Automatically remove detected patches
    bool alarmOnUnknown = true;    // Alert on unknown patches
    uint64_t scanIntervalMs = 1000; // How often to scan
    uint64_t maxPatchesAllowed = 0; // 0 = unlimited (with monitoring)
};

// ============================================================================
// The Antidote - AntiPatcher
// ============================================================================

class AntiPatcher {
public:
    AntiPatcher();
    ~AntiPatcher();
    
    // Initialize the antidote
    bool initialize();
    void shutdown();
    
    // =========================================================================
    // Baseline Management
    // =========================================================================
    
    // Create baseline of current code state
    std::string createBaseline(const std::string& regionName, 
                               void* baseAddress, 
                               size_t size,
                               bool isCritical = false);
    
    // Remove a baseline
    bool removeBaseline(const std::string& regionId);
    
    // Update baseline (after intentional changes)
    bool updateBaseline(const std::string& regionId);
    
    // Get all baselines
    std::vector<std::string> listBaselines() const;
    
    // =========================================================================
    // Patch Detection
    // =========================================================================
    
    // Scan a region for patches
    std::vector<DetectedPatch> scanRegion(const std::string& regionId);
    
    // Scan specific memory range
    std::vector<DetectedPatch> scanRange(void* start, size_t len);
    
    // Check if address is patched
    bool isPatched(void* address);
    
    // Get patch at address
    DetectedPatch getPatchAt(void* address);
    
    // Full system scan
    std::vector<DetectedPatch> scanAll();
    
    // =========================================================================
    // Patch Removal (The Cure)
    // =========================================================================
    
    // Remove a specific patch
    bool removePatch(const std::string& patchId);
    
    // Remove all patches in a region
    int removeAllPatches(const std::string& regionId);
    
    // Restore original code from baseline
    bool restoreBaseline(const std::string& regionId);
    
    // Emergency purge - remove ALL patches system-wide
    int emergencyPurge();
    
    // =========================================================================
    // Immunization
    // =========================================================================
    
    // Set immunization policy
    void setPolicy(const ImmunizationPolicy& policy);
    ImmunizationPolicy getPolicy() const;
    
    // Immunize a region (prevent future patching)
    bool immunize(const std::string& regionId);
    
    // De-immunize
    bool deimmunize(const std::string& regionId);
    
    // Check if region is immunized
    bool isImmunized(const std::string& regionId);
    
    // =========================================================================
    // Forensics
    // =========================================================================
    
    // Get evidence log
    std::vector<PatchEvidence> getEvidenceLog() const;
    
    // Export forensic report
    std::string exportForensicReport() const;
    
    // Analyze patch origin
    std::string analyzeOrigin(const DetectedPatch& patch);
    
    // =========================================================================
    // Monitoring
    // =========================================================================
    
    // Start continuous monitoring
    bool startMonitoring(uint64_t intervalMs = 1000);
    void stopMonitoring();
    
    // Set detection callback
    using DetectionCallback = std::function<void(const DetectedPatch&)>;
    void setDetectionCallback(DetectionCallback cb);
    
    // Set removal callback
    using RemovalCallback = std::function<void(const DetectedPatch&, bool success)>;
    void setRemovalCallback(RemovalCallback cb);
    
    // =========================================================================
    // Status & Statistics
    // =========================================================================
    
    struct Status {
        bool initialized;
        bool monitoring;
        size_t baselines;
        size_t detectedPatches;
        size_t removedPatches;
        size_t blockedAttempts;
        ImmunizationPolicy policy;
    };
    Status getStatus() const;
    
    void printStatus() const;
    
    // =========================================================================
    // Integration with The Bottle
    // =========================================================================
    
    // Register a patch as "authorized" (from The Bottle)
    void authorizePatch(const std::string& patchId, 
                       const std::string& source,
                       void* address,
                       size_t size);
    
    // Revoke authorization
    void revokeAuthorization(const std::string& patchId);
    
    // Check if patch is authorized
    bool isAuthorized(const std::string& patchId) const;
    
    // Get all authorized patches
    std::vector<std::string> getAuthorizedPatches() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Global AntiPatcher instance
AntiPatcher& GetAntiPatcher();

// Quick integrity check
bool VerifyCodeIntegrity(const std::string& regionName);

// Quick purge
int PurgeAllPatches();

// ============================================================================
// The Antidote vs The Bottle
// ============================================================================
/*

THE BOTTLE (HotPatcher):
- Purpose: Inject patches for performance/feature updates
- Philosophy: Change is good, embrace modification
- Actions: Register, validate, apply, monitor
- Safety: Rollback on failure

THE ANTIDOTE (AntiPatcher):
- Purpose: Detect and remove unauthorized modifications
- Philosophy: Trust but verify, maintain integrity
- Actions: Baseline, detect, remove, immunize
- Safety: Prevent malicious/unintended patches

SYMBIOSIS:
- The Bottle registers patches with The Antidote
- The Antidote allows authorized patches from The Bottle
- The Antidote removes unauthorized patches
- Together: Safe, controlled runtime modification

USAGE:

// Initialize both
GetHotPatcher().initialize();
GetAntiPatcher().initialize();

// Create baseline before any patches
GetAntiPatcher().createBaseline("engine_core", 
                                (void*)0x140000000, 
                                0x100000, 
                                true);

// Apply patch through The Bottle
auto patchId = GetHotPatcher().registerFunctionHook(...);
GetHotPatcher().apply(patchId);

// Authorize with The Antidote
GetAntiPatcher().authorizePatch(patchId, "HotPatcher", addr, size);

// The Antidote monitors and protects
GetAntiPatcher().startMonitoring(1000);

// If someone tries unauthorized patching:
// - Detected by The Antidote
// - Automatically removed (if policy allows)
// - Logged for forensics

*/

} // namespace Deep2

#endif // DEEP2_ANTIPATCHER_HPP
