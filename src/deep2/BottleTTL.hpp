// ============================================================================
// BottleTTL.hpp - Time-To-Live Management for Patches
//
// Automatically expires and removes patches after a specified duration.
// Prevents accumulation of stale hooks that slow down execution.
//
// Features:
//   - Per-patch TTL configuration
//   - Automatic cleanup of expired patches
//   - Renewal API for active patches
//   - Statistics on patch lifetime
//
// Copyright (c) 2026 RawrXD Sovereign Runtime - Bottle Expiration
// ============================================================================

#ifndef DEEP2_BOTTLE_TTL_HPP
#define DEEP2_BOTTLE_TTL_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <chrono>
#include <functional>

namespace Deep2 {

// ============================================================================
// TTL Configuration
// ============================================================================

struct TTLConfig {
    uint64_t defaultTTLMs = 3600000;        // 1 hour default
    uint64_t criticalTTLMs = 86400000;      // 24 hours for critical patches
    uint64_t emergencyTTLMs = 300000;       // 5 minutes for emergency patches
    
    bool autoCleanup = true;              // Automatically remove expired
    uint64_t cleanupIntervalMs = 60000;    // Check every minute
    
    bool warnBeforeExpire = true;         // Warn before expiration
    uint64_t warnThresholdMs = 300000;     // Warn 5 minutes before
    
    bool allowRenewal = true;             // Allow extending TTL
    uint64_t maxRenewals = 10;            // Max renewals per patch
};

// ============================================================================
// Patch Lifetime Entry
// ============================================================================

struct PatchLifetime {
    std::string patchId;
    uint64_t createdAt;
    uint64_t expiresAt;
    uint64_t lastRenewedAt;
    uint64_t renewalCount;
    bool isCritical;
    bool isEmergency;
    
    // Status
    enum class Status {
        ACTIVE,      // Patch is active and valid
        EXPIRING,    // Within warning threshold
        EXPIRED,     // Past expiration time
        RENEWED,     // Was expired but renewed
        REMOVED      // Has been cleaned up
    };
    Status status;
    
    // Check if expired
    bool IsExpired(uint64_t now) const { return now > expiresAt; }
    
    // Check if expiring soon
    bool IsExpiringSoon(uint64_t now, uint64_t threshold) const {
        return !IsExpired(now) && (expiresAt - now) < threshold;
    }
    
    // Time remaining
    uint64_t TimeRemaining(uint64_t now) const {
        return IsExpired(now) ? 0 : (expiresAt - now);
    }
};

// ============================================================================
// TTL Events
// ============================================================================

enum class TTLEventType {
    CREATED,      // Patch registered with TTL
    RENEWED,      // TTL extended
    EXPIRING,     // Within warning threshold
    EXPIRED,      // TTL reached
    CLEANED_UP    // Patch removed after expiration
};

struct TTLEvent {
    TTLEventType type;
    std::string patchId;
    uint64_t timestamp;
    uint64_t oldExpiry;
    uint64_t newExpiry;
    std::string reason;
};

// ============================================================================
// Bottle TTL Manager
// ============================================================================

class BottleTTL {
public:
    BottleTTL();
    ~BottleTTL();
    
    // Initialize
    bool Initialize(const TTLConfig& config = TTLConfig());
    void Shutdown();
    
    // =========================================================================
    // Registration
    // =========================================================================
    
    // Register a patch with TTL
    bool Register(const std::string& patchId, 
                  uint64_t ttlMs = 0,  // 0 = use default
                  bool isCritical = false,
                  bool isEmergency = false);
    
    // Unregister (manual removal)
    bool Unregister(const std::string& patchId);
    
    // =========================================================================
    // Renewal
    // =========================================================================
    
    // Extend TTL (renew the patch)
    bool Renew(const std::string& patchId, uint64_t extensionMs = 0);
    
    // Set new absolute expiry
    bool SetExpiry(const std::string& patchId, uint64_t newExpiryMs);
    
    // =========================================================================
    // Queries
    // =========================================================================
    
    // Get lifetime info
    bool GetLifetime(const std::string& patchId, PatchLifetime& out) const;
    
    // Check if patch is expired
    bool IsExpired(const std::string& patchId) const;
    
    // Check if patch is expiring soon
    bool IsExpiringSoon(const std::string& patchId, uint64_t thresholdMs = 0) const;
    
    // Get time remaining
    uint64_t TimeRemaining(const std::string& patchId) const;
    
    // List all active patches
    std::vector<std::string> GetActivePatches() const;
    
    // List expired patches
    std::vector<std::string> GetExpiredPatches() const;
    
    // List expiring soon
    std::vector<std::string> GetExpiringSoon(uint64_t thresholdMs = 0) const;
    
    // =========================================================================
    // Cleanup
    // =========================================================================
    
    // Manually trigger cleanup of expired patches
    size_t CleanupExpired();
    
    // Force remove all patches
    size_t PurgeAll();
    
    // =========================================================================
    // Event Handling
    // =========================================================================
    
    using EventCallback = std::function<void(const TTLEvent&)>;
    void SetEventCallback(EventCallback cb);
    
    // Get event history
    std::vector<TTLEvent> GetEventHistory() const;
    
    // Clear history
    void ClearHistory();
    
    // =========================================================================
    // Statistics
    // =========================================================================
    
    struct Stats {
        size_t activePatches;
        size_t expiredPatches;
        size_t totalRegistered;
        size_t totalRenewals;
        size_t totalCleanups;
        uint64_t avgLifetimeMs;
        double renewalRate;
    };
    
    Stats GetStats() const;
    void PrintStatus() const;
    
    // =========================================================================
    // Integration with HotPatcher
    // =========================================================================
    
    // Auto-register patches from HotPatcher
    void AutoRegisterFromHotPatcher();

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Global Instance
// ============================================================================

BottleTTL& GetBottleTTL();

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick register with default TTL
bool RegisterPatchWithTTL(const std::string& patchId, uint64_t ttlMinutes = 60);

// Quick renew
bool RenewPatch(const std::string& patchId, uint64_t extensionMinutes = 60);

// Check and cleanup
size_t CleanupExpiredPatches();

// ============================================================================
// Integration Example
// ============================================================================
/*

USAGE:

// Initialize
GetBottleTTL().Initialize();

// Register patch with 1 hour TTL
GetBottleTTL().Register("my_patch", 3600000);

// Or use convenience function
RegisterPatchWithTTL("my_patch", 60);  // 60 minutes

// Later... check if expiring
if (GetBottleTTL().IsExpiringSoon("my_patch", 300000)) {  // 5 min warning
    printf("Patch expiring soon!\n");
    
    // Renew it
    GetBottleTTL().Renew("my_patch", 3600000);  // Another hour
}

// Automatic cleanup runs in background
// Or manually trigger:
size_t cleaned = CleanupExpiredPatches();
printf("Cleaned up %zu expired patches\n", cleaned);

// Event handling
GetBottleTTL().SetEventCallback([](const TTLEvent& event) {
    switch (event.type) {
        case TTLEventType::EXPIRED:
            printf("Patch %s expired\n", event.patchId.c_str());
            // Automatically rollback
            GetHotPatcher().rollback(event.patchId);
            break;
        case TTLEventType::EXPIRING:
            printf("Patch %s expiring soon\n", event.patchId.c_str());
            break;
    }
});

*/

} // namespace Deep2

#endif // DEEP2_BOTTLE_TTL_HPP
