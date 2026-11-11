// Telemetry Injector - Self-Reflective Learning Loop
// Bridges PatchFirewall rejections back to ModelAdapter for real-time learning
//
// Architecture:
//   PatchFirewall rejects patch
//         |
//         v
//   TelemetryInjector captures violation
//         |
//         v
//   Ring Buffer stores RejectionFeedback
//         |
//         v
//   ModelAdapter reads on next inference
//         |
//         v
//   Model self-corrects

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <atomic>
#include <memory>
#include <functional>
#include <unordered_map>
#include <mutex>

namespace RawrXD {
namespace Kernel {

// Forward declarations
class BeaconEvent;

// ============================================================================
// Violation Types - Why patches get rejected
// ============================================================================

enum class ViolationCode : uint32_t {
    NONE = 0,
    
    // Memory safety
    UNALIGNED_PATCH = 1,           // AVX-512 alignment violation
    PROTECTED_MEMORY = 2,          // Attempted write to protected region
    OUT_OF_BOUNDS = 3,             // Target address outside valid aperture
    INVALID_POINTER = 4,           // Null or malformed pointer
    
    // Capability violations
    MISSING_CAPABILITY = 5,        // Agent lacks required capability
    LEASE_EXPIRED = 6,             // Resource lease timed out
    INSUFFICIENT_PRIVILEGE = 7,    // Attempted privileged operation
    
    // Semantic violations
    INVALID_INTENT_TYPE = 8,       // Intent type not recognized
    MALFORMED_PAYLOAD = 9,         // Payload failed validation
    POLICY_VIOLATION = 10,         // Violated organizational policy
    
    // Execution violations
    COMPILATION_FAILED = 11,       // Generated code doesn't compile
    LINK_ERROR = 12,               // Symbol resolution failed
    RUNTIME_CRASH = 13,            // VEH caught exception
    TIMEOUT = 14,                  // Execution exceeded time limit
    
    // Structural violations
    AST_MISMATCH = 15,             // Patch doesn't match AST structure
    SYMBOL_NOT_FOUND = 16,         // Target symbol doesn't exist
    TYPE_MISMATCH = 17,            // Type system violation
    DEPENDENCY_BREAK = 18,         // Patch breaks dependencies
    
    // Safety limits
    RECURSION_DEPTH = 19,          // Too many nested patches
    RATE_LIMIT = 20,               // Too many patches in time window
    RESOURCE_EXHAUSTION = 21,      // Out of memory/CPU
    
    CUSTOM = 255
};

const char* ViolationCodeToString(ViolationCode code);

// ============================================================================
// Rejection Feedback - What the model learns from
// ============================================================================

struct RejectionFeedback {
    uint64_t feedbackId;
    ViolationCode code;
    uint64_t timestamp;
    uint64_t intentId;
    uint64_t agentId;
    
    // Context
    std::string intentType;
    std::string targetSymbol;
    std::string targetFile;
    
    // Technical details
    uint64_t instructionPointer;
    uint64_t memoryAddress;
    std::string expectedType;
    std::string actualType;
    
    // Human-readable explanation
    std::string explanation;
    std::string suggestedFix;
    
    // Structured metadata for model consumption
    std::unordered_map<std::string, std::string> metadata;
    
    // Serialization
    std::string ToJson() const;
    std::string ToModelPrompt() const;  // Formatted for LLM context
};

// ============================================================================
// Success Feedback - What worked
// ============================================================================

struct SuccessFeedback {
    uint64_t feedbackId;
    uint64_t timestamp;
    uint64_t intentId;
    uint64_t agentId;
    
    std::string intentType;
    std::string targetSymbol;
    
    // Performance metrics
    double executionTimeMs;
    double latencyImprovement;
    double memoryImprovement;
    
    // Validation results
    bool testsPassed;
    uint32_t testsCount;
    bool securityScanPassed;
    bool performanceCheckPassed;
    
    // For learning
    std::string patchHash;
    std::string contextHash;
    std::unordered_map<std::string, std::string> metadata;
    
    std::string ToJson() const;
};

// ============================================================================
// Ring Buffer - Lock-free telemetry queue
// ============================================================================

class TelemetryRingBuffer {
public:
    explicit TelemetryRingBuffer(size_t capacity = 1024);
    
    // Rejection feedback
    bool PushRejection(const RejectionFeedback& feedback);
    bool PopRejection(RejectionFeedback& feedback);
    size_t GetRejectionCount() const;
    std::vector<RejectionFeedback> GetRecentRejections(size_t max = 10) const;
    void ClearRejections();
    
    // Success feedback
    bool PushSuccess(const SuccessFeedback& feedback);
    bool PopSuccess(SuccessFeedback& feedback);
    size_t GetSuccessCount() const;
    std::vector<SuccessFeedback> GetRecentSuccesses(size_t max = 10) const;
    
    // Statistics
    struct Stats {
        uint64_t totalRejections;
        uint64_t totalSuccesses;
        uint64_t rejectionsByCode[256];  // Histogram
        double averageExecutionTime;
        uint64_t lastRejectionTime;
        uint64_t lastSuccessTime;
    };
    Stats GetStats() const;
    
private:
    struct alignas(64) Slot {
        std::atomic<bool> occupied{false};
        RejectionFeedback rejection;
        SuccessFeedback success;
        bool isRejection;
    };
    
    std::vector<Slot> buffer_;
    std::atomic<size_t> writeIndex_{0};
    std::atomic<size_t> readIndex_{0};
    
    // Statistics
    mutable std::mutex statsMutex_;
    Stats stats_{};
};

// ============================================================================
// Telemetry Injector - The bridge
// ============================================================================

class TelemetryInjector {
public:
    static TelemetryInjector& Instance();
    
    // Initialization
    void Initialize(size_t ringBufferCapacity = 1024);
    void Shutdown();
    
    // Injection points - called by PatchFirewall, VEH, etc.
    void InjectRejection(ViolationCode code,
                         uint64_t intentId,
                         uint64_t agentId,
                         const std::string& explanation,
                         const std::unordered_map<std::string, std::string>& context);
    
    void InjectRejectionFromFirewall(const std::string& intentType,
                                      const std::string& targetSymbol,
                                      ViolationCode code,
                                      const std::string& reason);
    
    void InjectSuccess(const SuccessFeedback& feedback);
    void InjectSuccessFromTransaction(uint64_t intentId,
                                       const std::string& intentType,
                                       double executionTimeMs);
    
    // Consumption - called by ModelAdapter
    std::vector<RejectionFeedback> GetRejectionHistoryForAgent(uint64_t agentId, 
                                                                size_t max = 10) const;
    std::vector<RejectionFeedback> GetRejectionHistoryForIntentType(
        const std::string& intentType, size_t max = 10) const;
    
    std::string GenerateModelContext(uint64_t agentId) const;
    std::string GenerateLearningSummary() const;
    
    // Real-time subscription
    using FeedbackHandler = std::function<void(const RejectionFeedback&)>;
    uint64_t SubscribeToRejections(FeedbackHandler handler);
    void Unsubscribe(uint64_t subscriptionId);
    
    // Integration with BeaconBus
    void ConnectToBeaconBus();
    void DisconnectFromBeaconBus();
    
    // Statistics
    TelemetryRingBuffer::Stats GetStats() const;
    std::string GetStatsJson() const;
    
    // Learning mode
    void SetLearningMode(bool enabled) { learningMode_.store(enabled); }
    bool IsLearningMode() const { return learningMode_.load(); }
    
private:
    TelemetryInjector() = default;
    
    std::unique_ptr<TelemetryRingBuffer> ringBuffer_;
    std::atomic<bool> initialized_{false};
    std::atomic<bool> learningMode_{true};
    
    // Subscriptions
    std::unordered_map<uint64_t, FeedbackHandler> subscribers_;
    mutable std::mutex subscribersMutex_;
    std::atomic<uint64_t> nextSubscriptionId_{1};
    
    // Beacon integration
    uint64_t beaconSubscriptionId_{0};
    
    void NotifySubscribers(const RejectionFeedback& feedback);
    void OnBeaconEvent(const BeaconEvent& event);
};

// ============================================================================
// Convenience Macros
// ============================================================================

#define TELEMETRY_INJECTOR RawrXD::Kernel::TelemetryInjector::Instance()

#define INJECT_REJECTION(code, explanation) \
    TELEMETRY_INJECTOR.InjectRejection( \
        RawrXD::Kernel::ViolationCode::code, \
        intentId, \
        agentId, \
        explanation, \
        {})

#define INJECT_REJECTION_CTX(code, explanation, context) \
    TELEMETRY_INJECTOR.InjectRejection( \
        RawrXD::Kernel::ViolationCode::code, \
        intentId, \
        agentId, \
        explanation, \
        context)

} // namespace Kernel
} // namespace RawrXD
