// ============================================================================
// TrailBrake.cpp - Safety Anchor and Rollback System Implementation
//
// Detects when execution has gone "too far ahead" and automatically
// trails back to last known good anchor point.
//
// Copyright (c) 2026 RawrXD Sovereign Runtime
// ============================================================================

#include "TrailBrake.hpp"
#include "HotPatcher.hpp"
#include "AntiPatcher.hpp"
#include "HotPatcherSafety.hpp"
#include <algorithm>
#include <cmath>
#include <immintrin.h>

namespace Deep2 {

// ============================================================================
// Cryptographic Hash Helper (SHA-256 based state fingerprinting)
// ============================================================================
static void ComputeSHA256Block(uint32_t state[8], const uint8_t data[64]) {
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
    
    uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
    uint32_t e = state[4], f = state[5], g = state[6], h = state[7];
    uint32_t m[64];
    
    // Prepare message schedule
    for (int i = 0; i < 16; i++) {
        m[i] = (data[i * 4] << 24) | (data[i * 4 + 1] << 16) | 
               (data[i * 4 + 2] << 8) | data[i * 4 + 3];
    }
    for (int i = 16; i < 64; i++) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }
    
    // Main loop
    for (int i = 0; i < 64; i++) {
        uint32_t t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i];
        uint32_t t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
    }
    
    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
    
    #undef ROTR
    #undef CH
    #undef MAJ
    #undef EP0
    #undef EP1
    #undef SIG0
    #undef SIG1
}

static std::array<uint8_t, 32> ComputeStateHashImpl(const uint8_t* data, size_t len) {
    // SHA-256 initialization vector
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };
    
    // Process full blocks
    size_t i = 0;
    while (i + 64 <= len) {
        ComputeSHA256Block(state, data + i);
        i += 64;
    }
    
    // Final block with padding
    uint8_t finalBlock[64] = {};
    size_t remaining = len - i;
    memcpy(finalBlock, data + i, remaining);
    finalBlock[remaining] = 0x80;
    
    // If we can't fit the length, need another block
    if (remaining >= 56) {
        ComputeSHA256Block(state, finalBlock);
        memset(finalBlock, 0, 64);
    }
    
    // Append bit length (big-endian)
    uint64_t bitLen = len * 8;
    for (int j = 0; j < 8; j++) {
        finalBlock[63 - j] = (bitLen >> (j * 8)) & 0xFF;
    }
    ComputeSHA256Block(state, finalBlock);
    
    // Convert to bytes (big-endian)
    std::array<uint8_t, 32> hash;
    for (int j = 0; j < 8; j++) {
        hash[j * 4] = (state[j] >> 24) & 0xFF;
        hash[j * 4 + 1] = (state[j] >> 16) & 0xFF;
        hash[j * 4 + 2] = (state[j] >> 8) & 0xFF;
        hash[j * 4 + 3] = state[j] & 0xFF;
    }
    
    return hash;
}

// ============================================================================
// DriftMetrics Implementation
// ============================================================================

void DriftMetrics::CalculateComposite() {
    // Weighted combination of all drift factors
    float tokenWeight = 0.4f;
    float timeWeight = 0.3f;
    float progressWeight = 0.2f;
    float errorWeight = 0.1f;
    
    compositeDrift = 
        (tokenDriftRatio * tokenWeight) +
        (timeDriftRatio * timeWeight) +
        (progressDrift * progressWeight) +
        (errorRate * errorWeight);
    
    // Clamp to 0-1
    compositeDrift = std::max(0.0f, std::min(1.0f, compositeDrift));
}

// ============================================================================
// TrailBrake Implementation
// ============================================================================

class TrailBrake::Impl {
public:
    std::deque<AnchorPoint> anchors;
    std::deque<DriftMetrics> driftHistory;
    TrailBrakeConfig config;
    
    // Current expected values
    uint64_t expectedTokens = 0;
    uint64_t expectedTimeMs = 0;
    float expectedProgress = 0.0f;
    
    // Current actual values
    uint64_t actualTokens = 0;
    uint64_t actualTimeMs = 0;
    float actualProgress = 0.0f;
    uint32_t failureCount = 0;
    uint32_t rollbackCount = 0;
    
    BrakeState currentState = BrakeState::FREE;
    uint64_t lastAnchorTime = 0;
    
    mutable std::mutex mutex;
    EventCallback eventCallback;
    
    std::atomic<uint64_t> anchorsDropped{0};
    std::atomic<uint64_t> anchorsVerified{0};
    std::atomic<uint64_t> trailbacks{0};
    std::atomic<uint64_t> emergencyStops{0};
    std::atomic<uint64_t> tokensSaved{0};
    
    bool initialized = false;
    
    bool Initialize(const TrailBrakeConfig& cfg) {
        config = cfg;
        initialized = true;
        printf("[TrailBrake] Initialized (warning=%.1fx, brake=%.1fx, emergency=%.1fx)\n",
               config.warningThreshold, config.brakeThreshold, config.emergencyThreshold);
        return true;
    }
    
    void Shutdown() {
        anchors.clear();
        driftHistory.clear();
        initialized = false;
        printf("[TrailBrake] Shutdown\n");
    }
    
    std::string DropAnchor(const std::string& name, const std::string& context) {
        std::lock_guard<std::mutex> lock(mutex);
        
        uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        
        // Check if we should drop anchor (min interval)
        if (!anchors.empty() && actualTokens - anchors.back().tokenCount < config.minAnchorIntervalTokens) {
            return "";  // Too soon
        }
        
        AnchorPoint anchor;
        anchor.id = "anchor_" + std::to_string(now);
        anchor.name = name;
        anchor.timestamp = now;
        anchor.context = context;
        anchor.tokenCount = actualTokens;
        anchor.tokensFromLast = anchors.empty() ? 0 : actualTokens - anchors.back().tokenCount;
        anchor.timeFromLastMs = anchors.empty() ? 0 : now - anchors.back().timestamp;
        anchor.verified = false;
        
        // Compute state hash for rollback verification
        anchor.stateHash = ComputeStateHash();
        
        anchors.push_back(anchor);
        anchorsDropped++;
        
        // Prune old anchors
        while (anchors.size() > config.maxAnchors) {
            anchors.pop_front();
        }
        
        // Log event
        TrailBrakeEvent event;
        event.type = TrailBrakeEvent::Type::ANCHOR_CREATED;
        event.anchorId = anchor.id;
        event.timestamp = now;
        event.reason = name;
        if (eventCallback) eventCallback(event);
        
        printf("[TrailBrake] Dropped anchor: %s (tokens=%llu)\n", name.c_str(), actualTokens);
        return anchor.id;
    }
    
    std::vector<uint8_t> ComputeStateHash() {
        // SHA-256 hash of current metrics for state fingerprinting
        std::string data = std::to_string(actualTokens) + 
                          std::to_string(actualTimeMs) +
                          std::to_string(actualProgress);
        auto hash = ComputeStateHashImpl(reinterpret_cast<const uint8_t*>(data.data()), data.size());
        return std::vector<uint8_t>(hash.begin(), hash.end());
    }
    
    bool VerifyAnchor(const std::string& anchorId) {
        std::lock_guard<std::mutex> lock(mutex);
        
        for (auto& anchor : anchors) {
            if (anchor.id == anchorId) {
                anchor.verified = true;
                anchor.verifiedAt = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now().time_since_epoch()).count();
                anchorsVerified++;
                printf("[TrailBrake] Verified anchor: %s\n", anchor.name.c_str());
                return true;
            }
        }
        return false;
    }
    
    std::string GetLastVerifiedAnchor() const {
        std::lock_guard<std::mutex> lock(mutex);
        
        for (auto it = anchors.rbegin(); it != anchors.rend(); ++it) {
            if (it->verified) {
                return it->id;
            }
        }
        return "";
    }
    
    void ReportActualTokens(uint64_t tokens) {
        std::lock_guard<std::mutex> lock(mutex);
        actualTokens = tokens;
        CheckDrift();
    }
    
    void ReportFailure(const std::string& reason) {
        std::lock_guard<std::mutex> lock(mutex);
        failureCount++;
        
        TrailBrakeEvent event;
        event.type = TrailBrakeEvent::Type::DRIFT_WARNING;
        event.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        event.reason = reason;
        if (eventCallback) eventCallback(event);
        
        CheckDrift();
    }
    
    void CheckDrift() {
        if (expectedTokens == 0) return;
        
        DriftMetrics drift;
        drift.expectedTokens = expectedTokens;
        drift.actualTokens = actualTokens;
        drift.tokenDriftRatio = static_cast<float>(actualTokens) / static_cast<float>(expectedTokens);
        
        drift.expectedTimeMs = expectedTimeMs;
        drift.actualTimeMs = actualTimeMs;
        drift.timeDriftRatio = expectedTimeMs > 0 ? 
            static_cast<float>(actualTimeMs) / static_cast<float>(expectedTimeMs) : 1.0f;
        
        drift.expectedProgress = expectedProgress;
        drift.actualProgress = actualProgress;
        drift.progressDrift = std::abs(actualProgress - expectedProgress);
        
        drift.errorRate = static_cast<float>(failureCount) / std::max(1.0f, static_cast<float>(actualProgress * 100));
        drift.rollbackRate = static_cast<float>(rollbackCount) / std::max(1.0f, static_cast<float>(anchorsDropped));
        drift.consecutiveFailures = failureCount;
        
        drift.CalculateComposite();
        
        driftHistory.push_back(drift);
        while (driftHistory.size() > config.maxDriftHistory) {
            driftHistory.pop_front();
        }
        
        // Update brake state
        UpdateBrakeState(drift);
    }
    
    void UpdateBrakeState(const DriftMetrics& drift) {
        BrakeState oldState = currentState;
        
        if (drift.tokenDriftRatio >= config.emergencyThreshold ||
            drift.compositeDrift >= 0.9f) {
            currentState = BrakeState::EMERGENCY;
        } else if (drift.tokenDriftRatio >= config.brakeThreshold ||
                   drift.compositeDrift >= 0.7f) {
            currentState = BrakeState::BRAKING;
        } else if (drift.tokenDriftRatio >= config.warningThreshold ||
                   drift.compositeDrift >= 0.5f) {
            currentState = BrakeState::WARNING;
        } else {
            currentState = BrakeState::FREE;
        }
        
        if (currentState != oldState) {
            TrailBrakeEvent event;
            event.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::steady_clock::now().time_since_epoch()).count();
            event.drift = drift;
            
            switch (currentState) {
                case BrakeState::WARNING:
                    event.type = TrailBrakeEvent::Type::DRIFT_WARNING;
                    event.reason = "Drift warning threshold exceeded";
                    printf("[TrailBrake] WARNING: Drift=%.2fx\n", drift.tokenDriftRatio);
                    break;
                case BrakeState::BRAKING:
                    event.type = TrailBrakeEvent::Type::BRAKE_APPLIED;
                    event.reason = "Brake threshold exceeded";
                    printf("[TrailBrake] BRAKING: Drift=%.2fx\n", drift.tokenDriftRatio);
                    break;
                case BrakeState::EMERGENCY:
                    event.type = TrailBrakeEvent::Type::EMERGENCY_STOP;
                    event.reason = "Emergency threshold exceeded";
                    printf("[TrailBrake] EMERGENCY: Drift=%.2fx\n", drift.tokenDriftRatio);
                    if (config.autoRollback) {
                        TrailBack("");
                    }
                    break;
                default:
                    break;
            }
            
            if (eventCallback) eventCallback(event);
        }
    }
    
    bool TrailBack(const std::string& anchorId) {
        std::lock_guard<std::mutex> lock(mutex);
        
        std::string targetId = anchorId;
        if (targetId.empty()) {
            // Find last verified anchor
            for (auto it = anchors.rbegin(); it != anchors.rend(); ++it) {
                if (it->verified) {
                    targetId = it->id;
                    break;
                }
            }
        }
        
        if (targetId.empty()) {
            printf("[TrailBrake] ERROR: No verified anchor to trail back to\n");
            return false;
        }
        
        // Find the anchor
        AnchorPoint* target = nullptr;
        for (auto& anchor : anchors) {
            if (anchor.id == targetId) {
                target = &anchor;
                break;
            }
        }
        
        if (!target) {
            printf("[TrailBrake] ERROR: Anchor %s not found\n", targetId.c_str());
            return false;
        }
        
        printf("[TrailBrake] Trailing back to anchor: %s (saved %llu tokens)\n",
               target->name.c_str(), actualTokens - target->tokenCount);
        
        tokensSaved += actualTokens - target->tokenCount;
        trailbacks++;
        rollbackCount++;
        
        // Reset to anchor state
        actualTokens = target->tokenCount;
        currentState = BrakeState::TRAILING;
        
        // Apply antidote (purge patches since anchor)
        PurgeAllPatches();
        
        // Log event
        TrailBrakeEvent event;
        event.type = TrailBrakeEvent::Type::ROLLBACK_COMPLETE;
        event.anchorId = targetId;
        event.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        event.reason = "Trail back to anchor";
        if (eventCallback) eventCallback(event);
        
        currentState = BrakeState::FREE;
        return true;
    }
    
    bool EmergencyStop() {
        std::lock_guard<std::mutex> lock(mutex);
        
        printf("[TrailBrake] EMERGENCY STOP initiated\n");
        emergencyStops++;
        
        // Trail back immediately
        bool result = TrailBack("");
        
        // Log event
        TrailBrakeEvent event;
        event.type = TrailBrakeEvent::Type::EMERGENCY_STOP;
        event.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        event.reason = "Emergency stop";
        if (eventCallback) eventCallback(event);
        
        return result;
    }
    
    float GetBrakeIntensity() const {
        std::lock_guard<std::mutex> lock(mutex);
        
        if (currentState == BrakeState::EMERGENCY) return 1.0f;
        if (currentState == BrakeState::BRAKING) return config.brakeIntensity;
        if (currentState == BrakeState::WARNING) return config.brakeIntensity * 0.5f;
        return 0.0f;
    }
    
    uint64_t GetThrottledBudget(uint64_t requested) const {
        float intensity = GetBrakeIntensity();
        return static_cast<uint64_t>(requested * (1.0f - intensity));
    }
    
    TrailBrake::Stats GetStats() const {
        std::lock_guard<std::mutex> lock(mutex);
        
        TrailBrake::Stats stats;
        stats.anchorsDropped = anchorsDropped.load();
        stats.anchorsVerified = anchorsVerified.load();
        stats.trailbacks = trailbacks.load();
        stats.emergencyStops = emergencyStops.load();
        stats.tokensSaved = tokensSaved.load();
        
        // Calculate average drift
        if (!driftHistory.empty()) {
            float total = 0.0f;
            float maxDrift = 0.0f;
            for (const auto& d : driftHistory) {
                total += d.tokenDriftRatio;
                maxDrift = std::max(maxDrift, d.tokenDriftRatio);
            }
            stats.avgDrift = total / driftHistory.size();
            stats.maxDrift = maxDrift;
        } else {
            stats.avgDrift = 1.0f;
            stats.maxDrift = 1.0f;
        }
        
        return stats;
    }
};

// ============================================================================
// Public API
// ============================================================================

TrailBrake::TrailBrake() : impl_(std::make_unique<Impl>()) {}
TrailBrake::~TrailBrake() = default;

bool TrailBrake::Initialize(const TrailBrakeConfig& config) { return impl_->Initialize(config); }
void TrailBrake::Shutdown() { impl_->Shutdown(); }

std::string TrailBrake::DropAnchor(const std::string& name, const std::string& context) {
    return impl_->DropAnchor(name, context);
}

bool TrailBrake::VerifyAnchor(const std::string& anchorId) { return impl_->VerifyAnchor(anchorId); }
std::string TrailBrake::GetLastVerifiedAnchor() const { return impl_->GetLastVerifiedAnchor(); }

void TrailBrake::ReportActualTokens(uint64_t tokens) { impl_->ReportActualTokens(tokens); }
void TrailBrake::ReportFailure(const std::string& reason) { impl_->ReportFailure(reason); }

BrakeState TrailBrake::GetState() const { 
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->currentState; 
}

float TrailBrake::GetBrakeIntensity() const { return impl_->GetBrakeIntensity(); }

bool TrailBrake::TrailBack(const std::string& anchorId) { return impl_->TrailBack(anchorId); }
bool TrailBrake::EmergencyStop() { return impl_->EmergencyStop(); }

uint64_t TrailBrake::GetThrottledBudget(uint64_t requested) const { 
    return impl_->GetThrottledBudget(requested); 
}

void TrailBrake::SetEventCallback(EventCallback cb) { impl_->eventCallback = cb; }

TrailBrake::Stats TrailBrake::GetStats() const { return impl_->GetStats(); }

void TrailBrake::PrintStatus() const {
    auto stats = GetStats();
    
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║              TrailBrake Status - Safety Anchor                 ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Anchors Dropped:   %4llu                                          ║\n", stats.anchorsDropped);
    printf("║ Anchors Verified:  %4llu                                          ║\n", stats.anchorsVerified);
    printf("║ Trailbacks:        %4llu                                          ║\n", stats.trailbacks);
    printf("║ Emergency Stops:   %4llu                                          ║\n", stats.emergencyStops);
    printf("║ Tokens Saved:       %4llu                                          ║\n", stats.tokensSaved);
    printf("║ Avg Drift:         %6.2fx                                        ║\n", stats.avgDrift);
    printf("║ Max Drift:          %6.2fx                                        ║\n", stats.maxDrift);
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
}

// ============================================================================
// Global Instance
// ============================================================================

TrailBrake& GetTrailBrake() {
    static TrailBrake instance;
    return instance;
}

// ============================================================================
// Convenience Functions
// ============================================================================

std::string DropAnchor(const std::string& name) {
    return GetTrailBrake().DropAnchor(name);
}

bool IsSafeToProceed() {
    return GetTrailBrake().GetState() != BrakeState::EMERGENCY;
}

bool AutoTrailIfNeeded() {
    auto state = GetTrailBrake().GetState();
    if (state == BrakeState::BRAKING || state == BrakeState::EMERGENCY) {
        return GetTrailBrake().TrailBack();
    }
    return true;
}

} // namespace Deep2
