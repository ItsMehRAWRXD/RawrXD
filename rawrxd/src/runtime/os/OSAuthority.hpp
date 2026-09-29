// ============================================================================
// OSAuthority.hpp — Single Authority for Capability and Resource Access
// Ensures that every capability admission and resource allocation goes through
// one authority. Bypasses are counted and fail the gate.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <atomic>
#include <mutex>
#include <functional>

namespace RawrXD::OS {

// ---------------------------------------------------------------------------
// Authority metrics — fail-closed gate counters
// ---------------------------------------------------------------------------
struct AuthorityMetrics {
    std::atomic<uint64_t> totalAdmissions{0};
    std::atomic<uint64_t> allowedAdmissions{0};
    std::atomic<uint64_t> deniedAdmissions{0};
    std::atomic<uint64_t> degradedAdmissions{0};
    std::atomic<uint64_t> deferredAdmissions{0};
    std::atomic<uint64_t> totalAllocations{0};
    std::atomic<uint64_t> allowedAllocations{0};
    std::atomic<uint64_t> deniedAllocations{0};
    std::atomic<uint64_t> bypassAttempts{0};       // Any bypass fails the gate
    std::atomic<uint64_t> unauthorizedAccess{0};    // Access without authority

    bool gatePass() const {
        return bypassAttempts.load() == 0 &&
               unauthorizedAccess.load() == 0;
    }
};

// ---------------------------------------------------------------------------
// Authority — singleton, thread-safe
// All capability admissions and resource allocations MUST go through this.
// Direct access to resources without authority = bypass = gate failure.
// ---------------------------------------------------------------------------
class OSAuthority {
public:
    static OSAuthority& Instance();

    // Gate check: can this capability be admitted?
    // Returns true if authority allows, false if denied.
    // Increments bypass counter if called from unauthorized surface.
    bool authorizeAdmission(const std::string& capabilityId,
                            const std::string& callerSurface);

    // Gate check: can this resource be allocated to this capability?
    bool authorizeAllocation(const std::string& resourceId,
                             const std::string& capabilityId,
                             uint64_t amount);

    // Record a bypass attempt (any direct resource access without authority)
    void recordBypass(const std::string& detail);

    // Record unauthorized access (capability execution without admission)
    void recordUnauthorized(const std::string& detail);

    // Bind the authority to a caller surface (CLI, GUI, Agent, etc.)
    // Only bound surfaces can authorize admissions.
    void bindSurface(const std::string& surfaceId);
    bool isSurfaceBound(const std::string& surfaceId) const;

    // Metrics
    const AuthorityMetrics& metrics() const { return metrics_; }
    bool gatePass() const { return metrics_.gatePass(); }

    // Reset metrics (for testing)
    void resetMetrics();

private:
    OSAuthority() = default;
    ~OSAuthority() = default;
    OSAuthority(const OSAuthority&) = delete;
    OSAuthority& operator=(const OSAuthority&) = delete;

    AuthorityMetrics metrics_;
    mutable std::mutex mutex_;
    std::vector<std::string> boundSurfaces_;
};

} // namespace RawrXD::OS