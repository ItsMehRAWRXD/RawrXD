// ============================================================================
// TrailBrake.hpp - Safety Anchor and Rollback System
//
// Detects when execution has gone "too far ahead" of safe territory
// and automatically trails back to last known good anchor point.
//
// Features:
//   - Anchor point creation (known good states)
//   - Drift detection (deviation from expected path)
//   - Automatic rollback when thresholds exceeded
//   - Progressive trail braking (slow down before stopping)
//
// Copyright (c) 2026 RawrXD Sovereign Runtime - Safety Anchor System
// ============================================================================

#ifndef DEEP2_TRAIL_BRAKE_HPP
#define DEEP2_TRAIL_BRAKE_HPP

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <deque>
#include <unordered_map>
#include <memory>
#include <mutex>
#include <functional>
#include <chrono>

namespace Deep2 {

// ============================================================================
// Drift Metrics
// ============================================================================

struct DriftMetrics {
    // Token usage drift
    uint64_t expectedTokens;
    uint64_t actualTokens;
    float tokenDriftRatio;  // actual / expected
    
    // Time drift
    uint64_t expectedTimeMs;
    uint64_t actualTimeMs;
    float timeDriftRatio;
    
    // Progress drift
    float expectedProgress;
    float actualProgress;
    float progressDrift;
    
    // Stability metrics
    float errorRate;        // Errors per operation
    float rollbackRate;     // Rollbacks per operation
    uint32_t consecutiveFailures;
    
    // Composite drift score (0 = perfect, 1 = critical)
    float compositeDrift;
    
    void CalculateComposite();
};

// ============================================================================
// Anchor Point
// ============================================================================

struct AnchorPoint {
    std::string id;
    std::string name;
    uint64_t timestamp;
    
    // State snapshot
    std::vector<uint8_t> stateHash;  // SHA-256 of critical state
    uint64_t tokenCount;
    uint64_t instructionCount;
    
    // Context
    std::string context;    // What were we doing?
    std::string goalId;   // Associated goal
    
    // Validation
    bool verified;          // Was this state verified good?
    uint64_t verifiedAt;
    
    // Distance metrics
    uint64_t tokensFromLast;    // Tokens since last anchor
    uint64_t timeFromLastMs;    // Time since last anchor
};

// ============================================================================
// Trail Brake Configuration
// ============================================================================

struct TrailBrakeConfig {
    // Drift thresholds
    float warningThreshold = 1.5f;      // 50% over expected = warning
    float brakeThreshold = 2.0f;        // 100% over = apply brakes
    float emergencyThreshold = 3.0f;    // 200% over = emergency rollback
    
    // Anchor spacing
    uint64_t minAnchorIntervalTokens = 10000;  // Min tokens between anchors
    uint64_t maxAnchorIntervalTokens = 100000; // Max tokens before forced anchor
    uint64_t maxAnchorAgeMs = 300000;          // 5 minutes max anchor age
    
    // History
    size_t maxAnchors = 10;             // Keep last N anchors
    size_t maxDriftHistory = 100;     // Drift samples to keep
    
    // Progressive braking
    bool enableProgressiveBrake = true;
    float brakeIntensity = 0.5f;        // 0-1, how hard to brake
    
    // Auto-actions
    bool autoRollback = true;           // Automatically rollback on emergency
    bool autoThrottle = true;           // Throttle on warning
};

// ============================================================================
// Brake State
// ============================================================================

enum class BrakeState {
    FREE,       // No braking, full speed
    WARNING,    // Drift detected, monitoring
    BRAKING,    // Actively reducing speed/commitment
    TRAILING,   // Rolling back to last anchor
    EMERGENCY   // Emergency stop and full rollback
};

// ============================================================================
// TrailBrake Event
// ============================================================================

struct TrailBrakeEvent {
    enum class Type {
        ANCHOR_CREATED,
        DRIFT_WARNING,
        BRAKE_APPLIED,
        TRAIL_STARTED,
        EMERGENCY_STOP,
        ROLLBACK_COMPLETE,
        THROTTLE_APPLIED
    };
    
    Type type;
    std::string anchorId;
    uint64_t timestamp;
    DriftMetrics drift;
    std::string reason;
};

// ============================================================================
// TrailBrake - Safety Anchor System
// ============================================================================

class TrailBrake {
public:
    TrailBrake();
    ~TrailBrake();
    
    // Initialize
    bool Initialize(const TrailBrakeConfig& config = TrailBrakeConfig());
    void Shutdown();
    
    // =========================================================================
    // Anchor Management
    // =========================================================================
    
    // Create an anchor point (call when reaching known good state)
    std::string DropAnchor(const std::string& name, const std::string& context = "");
    
    // Verify anchor is good (mark as verified)
    bool VerifyAnchor(const std::string& anchorId);
    
    // Get last verified anchor
    std::string GetLastVerifiedAnchor() const;
    
    // Get anchor by ID
    bool GetAnchor(const std::string& id, AnchorPoint& out) const;
    
    // List all anchors
    std::vector<AnchorPoint> GetAnchors() const;
    
    // Clear old anchors (keep only recent)
    size_t PruneAnchors(size_t keepCount);
    
    // =========================================================================
    // Drift Monitoring
    // =========================================================================
    
    // Update expected metrics
    void SetExpectedTokens(uint64_t tokens);
    void SetExpectedTime(uint64_t timeMs);
    void SetExpectedProgress(float progress);
    
    // Report actual metrics
    void ReportActualTokens(uint64_t tokens);
    void ReportActualTime(uint64_t timeMs);
    void ReportActualProgress(float progress);
    void ReportFailure(const std::string& reason);
    
    // Calculate current drift
    DriftMetrics CalculateDrift() const;
    
    // =========================================================================
    // Brake Control
    // =========================================================================
    
    // Check if we should brake
    BrakeState CheckBrakeState() const;
    
    // Apply progressive brake
    float GetBrakeIntensity() const;
    
    // Trail back to anchor
    bool TrailBack(const std::string& anchorId = "");
    
    // Emergency stop and rollback
    bool EmergencyStop();
    
    // Get current state
    BrakeState GetState() const;
    
    // =========================================================================
    // Integration with The Bottle
    // =========================================================================
    
    // Auto-drop anchor before risky operations
    void BeforeRiskyOperation(const std::string& operationName);
    
    // Check if operation should proceed
    bool ShouldProceed() const;
    
    // Get throttled token budget
    uint64_t GetThrottledBudget(uint64_t requested) const;
    
    // =========================================================================
    // Statistics and Events
    // =========================================================================
    
    using EventCallback = std::function<void(const TrailBrakeEvent&)>;
    void SetEventCallback(EventCallback cb);
    
    struct Stats {
        uint64_t anchorsDropped;
        uint64_t anchorsVerified;
        uint64_t trailbacks;
        uint64_t emergencyStops;
        uint64_t tokensSaved;  // By early rollback
        float avgDrift;
        float maxDrift;
    };
    
    Stats GetStats() const;
    void PrintStatus() const;
    
    // Get drift history
    std::vector<DriftMetrics> GetDriftHistory() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

// ============================================================================
// Global Instance
// ============================================================================

TrailBrake& GetTrailBrake();

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick anchor drop
std::string DropAnchor(const std::string& name);

// Check if safe to proceed
bool IsSafeToProceed();

// Auto-trail if needed
bool AutoTrailIfNeeded();

// ============================================================================
// Integration Example
// ============================================================================
/*

USAGE:

// Initialize
GetTrailBrake().Initialize();

// Before risky operation
drop_anchor("before_xor_patch");

// Set expectations
GetTrailBrake().SetExpectedTokens(1000);

// Do work
apply_patch();

// Report actual
GetTrailBrake().ReportActualTokens(2500);  // Uh oh, 2.5x expected

// Check state
if (GetTrailBrake().GetState() == BrakeState::BRAKING) {
    printf("Braking applied, reducing token budget\n");
}

// Auto-trail if drift too high
if (!AutoTrailIfNeeded()) {
    printf("Rolled back to last anchor\n");
}

// Emergency stop if critical
if (GetTrailBrake().GetState() == BrakeState::EMERGENCY) {
    GetTrailBrake().EmergencyStop();
    printf("Emergency rollback complete\n");
}

*/

} // namespace Deep2

#endif // DEEP2_TRAIL_BRAKE_HPP
