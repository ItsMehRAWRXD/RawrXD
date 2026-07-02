// Sovereign_FlowControl_Production.cpp
// Phase 23A: Credit-Based Flow Control (CBFC) - Production Implementation
// Prevents buffer overflow in Ring Attention distributed swarm
//
// Build: cl.exe /O2 /EHsc /std:c++17 /DNDEBUG /Fe:SovereignFlowControl.dll

#include <windows.h>
#include <cstdint.h>
#include <cstring>
#include <atomic>
#include <chrono>
#include <vector>
#include <algorithm>

#define SOVEREIGN_FLOW_EXPORTS
#define SOVEREIGN_FLOW_API __declspec(dllexport)

namespace Sovereign {
namespace FlowControl {

// ============================================================================
// Constants (Production)
// ============================================================================

constexpr uint32_t DEFAULT_CREDIT_WINDOW = 500;        // Tokens
constexpr uint32_t MIN_CREDIT_WINDOW = 100;            // Minimum window
constexpr uint32_t MAX_CREDIT_WINDOW = 2000;           // Maximum window
constexpr uint32_t CREDIT_TIMEOUT_MS = 100;          // Credit return timeout
constexpr uint32_t CIRCUIT_BREAKER_THRESHOLD = 3;    // Failures before open
constexpr uint32_t CIRCUIT_BREAKER_RECOVERY_MS = 5000; // Recovery timeout
constexpr float    BDP_MULTIPLIER = 1.5f;            // Bandwidth-delay product

// ============================================================================
// Data Structures (Production)
// ============================================================================

typedef uint32_t NodeId;
constexpr NodeId INVALID_NODE = 0xFFFFFFFF;

enum class CircuitState : uint8_t {
    CLOSED = 0,      // Normal operation
    OPEN = 1,        // Failure detected, bypass
    HALF_OPEN = 2    // Testing recovery
};

enum class BackpressureLevel : uint8_t {
    NORMAL = 0,      // 0-50% capacity
    CAUTION = 1,     // 50-80% capacity
    WARNING = 2,     // 80-95% capacity
    CRITICAL = 3     // 95%+ capacity
};

struct CreditState {
    std::atomic<uint32_t> availableCredits{0};
    std::atomic<uint32_t> maxCredits{DEFAULT_CREDIT_WINDOW};
    std::atomic<uint32_t> tokensInFlight{0};
    std::atomic<uint64_t> lastCreditUpdate{0};
    std::atomic<float> processingLatencyMs{0.0f};
    std::atomic<float> measuredRttMs{0.0f};
};

struct CircuitBreaker {
    std::atomic<CircuitState> state{CircuitState::CLOSED};
    std::atomic<uint32_t> failureCount{0};
    std::atomic<uint32_t> successCount{0};
    std::atomic<uint64_t> lastFailureTime{0};
    std::atomic<uint64_t> lastStateChange{0};
    NodeId bypassRoute{INVALID_NODE};
};

struct FlowMetrics {
    std::atomic<uint64_t> creditsGranted{0};
    std::atomic<uint64_t> creditsReturned{0};
    std::atomic<uint64_t> creditsTimedOut{0};
    std::atomic<uint64_t> tokensSent{0};
    std::atomic<uint64_t> tokensAcked{0};
    std::atomic<uint64_t> tokensDropped{0};
    std::atomic<uint64_t> circuitBreakerTrips{0};
    std::atomic<uint64_t> backpressureEvents{0};
};

// ============================================================================
// Credit Manager (Production)
// ============================================================================

class CreditManager {
public:
    std::vector<CreditState> credits;
    FlowMetrics metrics;
    
    bool Initialize(uint32_t numNeighbors) {
        credits.resize(numNeighbors);
        for (auto& credit : credits) {
            credit.availableCredits.store(DEFAULT_CREDIT_WINDOW);
            credit.maxCredits.store(DEFAULT_CREDIT_WINDOW);
            credit.tokensInFlight.store(0);
            credit.lastCreditUpdate.store(GetTimestampMs());
        }
        return true;
    }
    
    // Grant credits to downstream neighbor
    bool GrantCredits(NodeId neighborId, uint32_t amount) {
        if (neighborId >= credits.size()) return false;
        
        auto& credit = credits[neighborId];
        uint32_t currentMax = credit.maxCredits.load();
        uint32_t newMax = std::min(currentMax + amount, MAX_CREDIT_WINDOW);
        
        credit.maxCredits.store(newMax);
        credit.availableCredits.fetch_add(amount);
        credit.lastCreditUpdate.store(GetTimestampMs());
        
        metrics.creditsGranted.fetch_add(amount);
        return true;
    }
    
    // Consume credits before sending tokens
    bool ConsumeCredits(NodeId neighborId, uint32_t tokens) {
        if (neighborId >= credits.size()) return false;
        
        auto& credit = credits[neighborId];
        uint32_t available = credit.availableCredits.load();
        
        // Check if enough credits available
        if (available < tokens) {
            return false; // Backpressure - don't send
        }
        
        // Atomically consume credits
        uint32_t expected = available;
        while (!credit.availableCredits.compare_exchange_weak(expected, expected - tokens)) {
            if (expected < tokens) return false;
        }
        
        credit.tokensInFlight.fetch_add(tokens);
        metrics.tokensSent.fetch_add(tokens);
        
        return true;
    }
    
    // Return credits from downstream (ACK received)
    bool ReturnCredits(NodeId neighborId, uint32_t amount, uint32_t processedTokens) {
        if (neighborId >= credits.size()) return false;
        
        auto& credit = credits[neighborId];
        credit.availableCredits.fetch_add(amount);
        credit.tokensInFlight.fetch_sub(processedTokens);
        credit.lastCreditUpdate.store(GetTimestampMs());
        
        metrics.creditsReturned.fetch_add(amount);
        metrics.tokensAcked.fetch_add(processedTokens);
        
        return true;
    }
    
    // Check for credit timeouts (called periodically)
    void CheckTimeouts() {
        uint64_t now = GetTimestampMs();
        
        for (size_t i = 0; i < credits.size(); i++) {
            auto& credit = credits[i];
            uint64_t lastUpdate = credit.lastCreditUpdate.load();
            
            if (now - lastUpdate > CREDIT_TIMEOUT_MS) {
                // Timeout - auto-return credits
                uint32_t inFlight = credit.tokensInFlight.load();
                if (inFlight > 0) {
                    credit.availableCredits.fetch_add(inFlight);
                    credit.tokensInFlight.store(0);
                    metrics.creditsTimedOut.fetch_add(inFlight);
                }
            }
        }
    }
    
    // Get minimum available credits across all neighbors
    uint32_t GetMinCredits() const {
        if (credits.empty()) return 0;
        
        uint32_t minCredits = UINT32_MAX;
        for (const auto& credit : credits) {
            uint32_t available = credit.availableCredits.load();
            if (available < minCredits) {
                minCredits = available;
            }
        }
        return minCredits;
    }
    
    // Calculate safe token rate based on credits
    float CalculateSafeRate(float targetLatencyMs) const {
        uint32_t minCredits = GetMinCredits();
        if (minCredits == 0) return 0.0f;
        if (targetLatencyMs <= 0) return 0.0f;
        
        // Rate = credits / latency (with safety margin)
        float baseRate = static_cast<float>(minCredits) / targetLatencyMs;
        return baseRate * 0.8f; // 80% safety margin
    }
    
private:
    static uint64_t GetTimestampMs() {
        return GetTickCount64();
    }
};

// ============================================================================
// Circuit Breaker (Production)
// ============================================================================

class CircuitBreakerManager {
public:
    std::vector<CircuitBreaker> circuits;
    
    bool Initialize(uint32_t numNeighbors) {
        circuits.resize(numNeighbors);
        for (auto& circuit : circuits) {
            circuit.state.store(CircuitState::CLOSED);
            circuit.failureCount.store(0);
            circuit.successCount.store(0);
            circuit.lastFailureTime.store(0);
            circuit.lastStateChange.store(GetTimestampMs());
            circuit.bypassRoute = INVALID_NODE;
        }
        return true;
    }
    
    // Record success on a circuit
    void RecordSuccess(NodeId neighborId) {
        if (neighborId >= circuits.size()) return;
        
        auto& circuit = circuits[neighborId];
        CircuitState currentState = circuit.state.load();
        
        if (currentState == CircuitState::HALF_OPEN) {
            uint32_t successes = circuit.successCount.fetch_add(1) + 1;
            if (successes >= 3) {
                // Enough successes - close circuit
                circuit.state.store(CircuitState::CLOSED);
                circuit.failureCount.store(0);
                circuit.lastStateChange.store(GetTimestampMs());
            }
        } else if (currentState == CircuitState::CLOSED) {
            circuit.failureCount.store(0); // Reset on success
        }
    }
    
    // Record failure on a circuit
    void RecordFailure(NodeId neighborId) {
        if (neighborId >= circuits.size()) return;
        
        auto& circuit = circuits[neighborId];
        CircuitState currentState = circuit.state.load();
        
        if (currentState == CircuitState::CLOSED) {
            uint32_t failures = circuit.failureCount.fetch_add(1) + 1;
            circuit.lastFailureTime.store(GetTimestampMs());
            
            if (failures >= CIRCUIT_BREAKER_THRESHOLD) {
                // Trip circuit
                circuit.state.store(CircuitState::OPEN);
                circuit.lastStateChange.store(GetTimestampMs());
            }
        } else if (currentState == CircuitState::HALF_OPEN) {
            // Failure in half-open - back to open
            circuit.state.store(CircuitState::OPEN);
            circuit.successCount.store(0);
            circuit.lastStateChange.store(GetTimestampMs());
        }
    }
    
    // Check if circuit allows traffic
    bool CanSend(NodeId neighborId) {
        if (neighborId >= circuits.size()) return false;
        
        auto& circuit = circuits[neighborId];
        CircuitState state = circuit.state.load();
        
        if (state == CircuitState::CLOSED) {
            return true;
        } else if (state == CircuitState::OPEN) {
            // Check if recovery timeout elapsed
            uint64_t now = GetTimestampMs();
            uint64_t lastChange = circuit.lastStateChange.load();
            
            if (now - lastChange > CIRCUIT_BREAKER_RECOVERY_MS) {
                // Transition to half-open
                circuit.state.store(CircuitState::HALF_OPEN);
                circuit.successCount.store(0);
                circuit.lastStateChange.store(now);
                return true; // Allow test traffic
            }
            return false; // Circuit open
        } else { // HALF_OPEN
            return true; // Allow test traffic
        }
    }
    
    // Get bypass route for failed node
    NodeId GetBypassRoute(NodeId failedNode) {
        if (failedNode >= circuits.size()) return INVALID_NODE;
        return circuits[failedNode].bypassRoute;
    }
    
    // Set bypass route
    void SetBypassRoute(NodeId failedNode, NodeId bypassNode) {
        if (failedNode >= circuits.size()) return;
        circuits[failedNode].bypassRoute = bypassNode;
    }
    
    // Get circuit state
    CircuitState GetState(NodeId neighborId) const {
        if (neighborId >= circuits.size()) return CircuitState::OPEN;
        return circuits[neighborId].state.load();
    }
    
private:
    static uint64_t GetTimestampMs() {
        return GetTickCount64();
    }
};

// ============================================================================
// Backpressure Monitor (Production)
// ============================================================================

class BackpressureMonitor {
public:
    struct Thresholds {
        uint32_t cautionThreshold;    // 50%
        uint32_t warningThreshold;    // 80%
        uint32_t criticalThreshold;   // 95%
        uint32_t maxCapacity;
    };
    
    Thresholds thresholds;
    std::atomic<uint32_t> currentUsage{0};
    std::atomic<BackpressureLevel> currentLevel{BackpressureLevel::NORMAL};
    
    void Initialize(uint32_t maxCapacity) {
        thresholds.maxCapacity = maxCapacity;
        thresholds.cautionThreshold = maxCapacity * 50 / 100;
        thresholds.warningThreshold = maxCapacity * 80 / 100;
        thresholds.criticalThreshold = maxCapacity * 95 / 100;
    }
    
    void UpdateUsage(uint32_t usage) {
        currentUsage.store(usage);
        
        BackpressureLevel newLevel;
        if (usage >= thresholds.criticalThreshold) {
            newLevel = BackpressureLevel::CRITICAL;
        } else if (usage >= thresholds.warningThreshold) {
            newLevel = BackpressureLevel::WARNING;
        } else if (usage >= thresholds.cautionThreshold) {
            newLevel = BackpressureLevel::CAUTION;
        } else {
            newLevel = BackpressureLevel::NORMAL;
        }
        
        currentLevel.store(newLevel);
    }
    
    BackpressureLevel GetLevel() const {
        return currentLevel.load();
    }
    
    float GetReductionFactor() const {
        switch (currentLevel.load()) {
            case BackpressureLevel::NORMAL:    return 1.0f;
            case BackpressureLevel::CAUTION:   return 0.75f;
            case BackpressureLevel::WARNING:   return 0.5f;
            case BackpressureLevel::CRITICAL:  return 0.0f;
            default: return 1.0f;
        }
    }
};

// ============================================================================
// Main Flow Control (Production)
// ============================================================================

class FlowController {
public:
    CreditManager creditManager;
    CircuitBreakerManager circuitBreaker;
    BackpressureMonitor backpressure;
    FlowMetrics metrics;
    
    std::atomic<bool> running{false};
    std::atomic<float> targetRateTps{336.7f};
    std::atomic<float> currentRateTps{0.0f};
    
    bool Initialize(uint32_t numNeighbors, uint32_t bufferCapacity) {
        if (!creditManager.Initialize(numNeighbors)) return false;
        if (!circuitBreaker.Initialize(numNeighbors)) return false;
        backpressure.Initialize(bufferCapacity);
        running.store(true);
        return true;
    }
    
    // Main flow control decision
    bool CanSend(NodeId neighborId, uint32_t tokens) {
        // Check circuit breaker
        if (!circuitBreaker.CanSend(neighborId)) {
            return false;
        }
        
        // Check credits
        if (!creditManager.ConsumeCredits(neighborId, tokens)) {
            return false;
        }
        
        return true;
    }
    
    // Process ACK from downstream
    void ProcessAck(NodeId neighborId, uint32_t creditsReturned, 
                    uint32_t tokensProcessed, float latencyMs) {
        creditManager.ReturnCredits(neighborId, creditsReturned, tokensProcessed);
        circuitBreaker.RecordSuccess(neighborId);
        
        // Update RTT measurement
        if (neighborId < creditManager.credits.size()) {
            creditManager.credits[neighborId].measuredRttMs.store(latencyMs);
        }
    }
    
    // Process NACK or timeout
    void ProcessFailure(NodeId neighborId) {
        circuitBreaker.RecordFailure(neighborId);
        metrics.circuitBreakerTrips.fetch_add(1);
    }
    
    // Periodic maintenance
    void Tick() {
        if (!running.load()) return;
        
        // Check credit timeouts
        creditManager.CheckTimeouts();
        
        // Calculate safe rate
        float safeRate = creditManager.CalculateSafeRate(2.97f); // Target latency
        float reduction = backpressure.GetReductionFactor();
        currentRateTps.store(safeRate * reduction);
        
        // Update metrics
        if (backpressure.GetLevel() != BackpressureLevel::NORMAL) {
            metrics.backpressureEvents.fetch_add(1);
        }
    }
    
    // Get current flow metrics
    void GetMetrics(FlowMetrics* outMetrics) const {
        if (!outMetrics) return;
        
        outMetrics->creditsGranted.store(metrics.creditsGranted.load());
        outMetrics->creditsReturned.store(metrics.creditsReturned.load());
        outMetrics->creditsTimedOut.store(metrics.creditsTimedOut.load());
        outMetrics->tokensSent.store(metrics.tokensSent.load());
        outMetrics->tokensAcked.store(metrics.tokensAcked.load());
        outMetrics->tokensDropped.store(metrics.tokensDropped.load());
    }
    
    void Shutdown() {
        running.store(false);
    }
};

// ============================================================================
// C API (Production)
// ============================================================================

extern "C" {

SOVEREIGN_FLOW_API void* Sovereign_FlowControl_Create() {
    return new FlowController();
}

SOVEREIGN_FLOW_API void Sovereign_FlowControl_Destroy(void* controller) {
    delete static_cast<FlowController*>(controller);
}

SOVEREIGN_FLOW_API int Sovereign_FlowControl_Initialize(void* controller,
                                                         uint32_t numNeighbors,
                                                         uint32_t bufferCapacity) {
    if (!controller) return -1;
    auto* fc = static_cast<FlowController*>(controller);
    return fc->Initialize(numNeighbors, bufferCapacity) ? 0 : -1;
}

SOVEREIGN_FLOW_API int Sovereign_FlowControl_CanSend(void* controller,
                                                       uint32_t neighborId,
                                                       uint32_t tokens) {
    if (!controller) return 0;
    auto* fc = static_cast<FlowController*>(controller);
    return fc->CanSend(neighborId, tokens) ? 1 : 0;
}

SOVEREIGN_FLOW_API void Sovereign_FlowControl_ProcessAck(void* controller,
                                                          uint32_t neighborId,
                                                          uint32_t creditsReturned,
                                                          uint32_t tokensProcessed,
                                                          float latencyMs) {
    if (!controller) return;
    auto* fc = static_cast<FlowController*>(controller);
    fc->ProcessAck(neighborId, creditsReturned, tokensProcessed, latencyMs);
}

SOVEREIGN_FLOW_API void Sovereign_FlowControl_ProcessFailure(void* controller,
                                                              uint32_t neighborId) {
    if (!controller) return;
    auto* fc = static_cast<FlowController*>(controller);
    fc->ProcessFailure(neighborId);
}

SOVEREIGN_FLOW_API void Sovereign_FlowControl_Tick(void* controller) {
    if (!controller) return;
    auto* fc = static_cast<FlowController*>(controller);
    fc->Tick();
}

SOVEREIGN_FLOW_API float Sovereign_FlowControl_GetCurrentRate(void* controller) {
    if (!controller) return 0.0f;
    auto* fc = static_cast<FlowController*>(controller);
    return fc->currentRateTps.load();
}

SOVEREIGN_FLOW_API uint32_t Sovereign_FlowControl_GetMinCredits(void* controller) {
    if (!controller) return 0;
    auto* fc = static_cast<FlowController*>(controller);
    return fc->creditManager.GetMinCredits();
}

} // extern "C"

} // namespace FlowControl
} // namespace Sovereign

// DLL entry point
BOOL APIENTRY DllMain(HMODULE hModule, DWORD reason, LPVOID lpReserved) {
    return TRUE;
}