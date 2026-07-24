// Telemetry Injector - Implementation
// Bridges PatchFirewall rejections back to ModelAdapter for real-time learning

#include "TelemetryInjector.hpp"
#include "AgentKernel.hpp"

#include <sstream>
#include <chrono>
#include <algorithm>

namespace RawrXD {
namespace Kernel {

// ============================================================================
// Utility Functions
// ============================================================================

const char* ViolationCodeToString(ViolationCode code) {
    switch (code) {
        case ViolationCode::NONE: return "NONE";
        case ViolationCode::UNALIGNED_PATCH: return "UNALIGNED_PATCH";
        case ViolationCode::PROTECTED_MEMORY: return "PROTECTED_MEMORY";
        case ViolationCode::OUT_OF_BOUNDS: return "OUT_OF_BOUNDS";
        case ViolationCode::INVALID_POINTER: return "INVALID_POINTER";
        case ViolationCode::MISSING_CAPABILITY: return "MISSING_CAPABILITY";
        case ViolationCode::LEASE_EXPIRED: return "LEASE_EXPIRED";
        case ViolationCode::INSUFFICIENT_PRIVILEGE: return "INSUFFICIENT_PRIVILEGE";
        case ViolationCode::INVALID_INTENT_TYPE: return "INVALID_INTENT_TYPE";
        case ViolationCode::MALFORMED_PAYLOAD: return "MALFORMED_PAYLOAD";
        case ViolationCode::POLICY_VIOLATION: return "POLICY_VIOLATION";
        case ViolationCode::COMPILATION_FAILED: return "COMPILATION_FAILED";
        case ViolationCode::LINK_ERROR: return "LINK_ERROR";
        case ViolationCode::RUNTIME_CRASH: return "RUNTIME_CRASH";
        case ViolationCode::TIMEOUT: return "TIMEOUT";
        case ViolationCode::AST_MISMATCH: return "AST_MISMATCH";
        case ViolationCode::SYMBOL_NOT_FOUND: return "SYMBOL_NOT_FOUND";
        case ViolationCode::TYPE_MISMATCH: return "TYPE_MISMATCH";
        case ViolationCode::DEPENDENCY_BREAK: return "DEPENDENCY_BREAK";
        case ViolationCode::RECURSION_DEPTH: return "RECURSION_DEPTH";
        case ViolationCode::RATE_LIMIT: return "RATE_LIMIT";
        case ViolationCode::RESOURCE_EXHAUSTION: return "RESOURCE_EXHAUSTION";
        case ViolationCode::CUSTOM: return "CUSTOM";
        default: return "UNKNOWN";
    }
}

static uint64_t GetTimestamp() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()
    ).count();
}

// ============================================================================
// RejectionFeedback Implementation
// ============================================================================

std::string RejectionFeedback::ToJson() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"feedbackId\":" << feedbackId << ",";
    ss << "\"code\":\"" << ViolationCodeToString(code) << "\",";
    ss << "\"timestamp\":" << timestamp << ",";
    ss << "\"intentId\":" << intentId << ",";
    ss << "\"agentId\":" << agentId << ",";
    ss << "\"intentType\":\"" << intentType << "\",";
    ss << "\"targetSymbol\":\"" << targetSymbol << "\",";
    ss << "\"targetFile\":\"" << targetFile << "\",";
    ss << "\"explanation\":\"" << explanation << "\",";
    ss << "\"suggestedFix\":\"" << suggestedFix << "\",";
    ss << "\"metadata\":{";
    bool first = true;
    for (const auto& [key, value] : metadata) {
        if (!first) ss << ",";
        ss << "\"" << key << "\":\"" << value << "\"";
        first = false;
    }
    ss << "}}";
    return ss.str();
}

std::string RejectionFeedback::ToModelPrompt() const {
    std::stringstream ss;
    ss << "[SYSTEM FEEDBACK]\n";
    ss << "Your previous intent was rejected.\n\n";
    ss << "Intent: " << intentType << "\n";
    ss << "Target: " << targetSymbol << " (" << targetFile << ")\n";
    ss << "Rejection: " << ViolationCodeToString(code) << "\n";
    ss << "Explanation: " << explanation << "\n";
    if (!suggestedFix.empty()) {
        ss << "Suggested Fix: " << suggestedFix << "\n";
    }
    ss << "\nPlease adjust your approach and try again.";
    return ss.str();
}

// ============================================================================
// SuccessFeedback Implementation
// ============================================================================

std::string SuccessFeedback::ToJson() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"feedbackId\":" << feedbackId << ",";
    ss << "\"timestamp\":" << timestamp << ",";
    ss << "\"intentId\":" << intentId << ",";
    ss << "\"agentId\":" << agentId << ",";
    ss << "\"intentType\":\"" << intentType << "\",";
    ss << "\"targetSymbol\":\"" << targetSymbol << "\",";
    ss << "\"executionTimeMs\":" << executionTimeMs << ",";
    ss << "\"latencyImprovement\":" << latencyImprovement << ",";
    ss << "\"memoryImprovement\":" << memoryImprovement << ",";
    ss << "\"testsPassed\":" << (testsPassed ? "true" : "false") << ",";
    ss << "\"testsCount\":" << testsCount << ",";
    ss << "\"securityScanPassed\":" << (securityScanPassed ? "true" : "false") << ",";
    ss << "\"performanceCheckPassed\":" << (performanceCheckPassed ? "true" : "false") << ",";
    ss << "\"patchHash\":\"" << patchHash << "\"";
    ss << "}";
    return ss.str();
}

// ============================================================================
// TelemetryRingBuffer Implementation
// ============================================================================

TelemetryRingBuffer::TelemetryRingBuffer(size_t capacity) 
    : buffer_(capacity) {}

bool TelemetryRingBuffer::PushRejection(const RejectionFeedback& feedback) {
    size_t writeIdx = writeIndex_.fetch_add(1);
    size_t slotIdx = writeIdx % buffer_.size();
    
    Slot& slot = buffer_[slotIdx];
    
    // Wait if slot is occupied (should be brief)
    int spins = 0;
    while (slot.occupied.load() && spins < 1000) {
        spins++;
    }
    
    if (slot.occupied.load()) {
        // Slot still occupied - overwrite (old data lost)
    }
    
    slot.rejection = feedback;
    slot.isRejection = true;
    slot.occupied.store(true);
    
    // Update stats
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_.totalRejections++;
    stats_.rejectionsByCode[static_cast<uint32_t>(feedback.code)]++;
    stats_.lastRejectionTime = feedback.timestamp;
    
    return true;
}

bool TelemetryRingBuffer::PopRejection(RejectionFeedback& feedback) {
    size_t readIdx = readIndex_.load();
    size_t writeIdx = writeIndex_.load();
    
    if (readIdx >= writeIdx) {
        return false; // Empty
    }
    
    size_t slotIdx = readIdx % buffer_.size();
    Slot& slot = buffer_[slotIdx];
    
    if (!slot.occupied.load()) {
        return false;
    }
    
    if (!slot.isRejection) {
        // Skip success entries
        readIndex_.fetch_add(1);
        return false;
    }
    
    feedback = slot.rejection;
    slot.occupied.store(false);
    readIndex_.fetch_add(1);
    
    return true;
}

size_t TelemetryRingBuffer::GetRejectionCount() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_.totalRejections;
}

std::vector<RejectionFeedback> TelemetryRingBuffer::GetRecentRejections(size_t max) const {
    std::vector<RejectionFeedback> result;
    
    size_t writeIdx = writeIndex_.load();
    size_t count = std::min(max, buffer_.size());
    
    for (size_t i = 0; i < count; ++i) {
        size_t idx = (writeIdx - 1 - i) % buffer_.size();
        const Slot& slot = buffer_[idx];
        if (slot.occupied.load() && slot.isRejection) {
            result.push_back(slot.rejection);
        }
    }
    
    return result;
}

void TelemetryRingBuffer::ClearRejections() {
    for (auto& slot : buffer_) {
        if (slot.isRejection) {
            slot.occupied.store(false);
        }
    }
}

bool TelemetryRingBuffer::PushSuccess(const SuccessFeedback& feedback) {
    size_t writeIdx = writeIndex_.fetch_add(1);
    size_t slotIdx = writeIdx % buffer_.size();
    
    Slot& slot = buffer_[slotIdx];
    
    int spins = 0;
    while (slot.occupied.load() && spins < 1000) {
        spins++;
    }
    
    slot.success = feedback;
    slot.isRejection = false;
    slot.occupied.store(true);
    
    // Update stats
    std::lock_guard<std::mutex> lock(statsMutex_);
    stats_.totalSuccesses++;
    stats_.lastSuccessTime = feedback.timestamp;
    stats_.averageExecutionTime = 
        (stats_.averageExecutionTime * (stats_.totalSuccesses - 1) + feedback.executionTimeMs) 
        / stats_.totalSuccesses;
    
    return true;
}

bool TelemetryRingBuffer::PopSuccess(SuccessFeedback& feedback) {
    size_t readIdx = readIndex_.load();
    size_t writeIdx = writeIndex_.load();
    
    if (readIdx >= writeIdx) {
        return false;
    }
    
    size_t slotIdx = readIdx % buffer_.size();
    Slot& slot = buffer_[slotIdx];
    
    if (!slot.occupied.load()) {
        return false;
    }
    
    if (slot.isRejection) {
        readIndex_.fetch_add(1);
        return false;
    }
    
    feedback = slot.success;
    slot.occupied.store(false);
    readIndex_.fetch_add(1);
    
    return true;
}

size_t TelemetryRingBuffer::GetSuccessCount() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_.totalSuccesses;
}

std::vector<SuccessFeedback> TelemetryRingBuffer::GetRecentSuccesses(size_t max) const {
    std::vector<SuccessFeedback> result;
    
    size_t writeIdx = writeIndex_.load();
    size_t count = std::min(max, buffer_.size());
    
    for (size_t i = 0; i < count; ++i) {
        size_t idx = (writeIdx - 1 - i) % buffer_.size();
        const Slot& slot = buffer_[idx];
        if (slot.occupied.load() && !slot.isRejection) {
            result.push_back(slot.success);
        }
    }
    
    return result;
}

TelemetryRingBuffer::Stats TelemetryRingBuffer::GetStats() const {
    std::lock_guard<std::mutex> lock(statsMutex_);
    return stats_;
}

// ============================================================================
// TelemetryInjector Implementation
// ============================================================================

TelemetryInjector& TelemetryInjector::Instance() {
    static TelemetryInjector instance;
    return instance;
}

void TelemetryInjector::Initialize(size_t ringBufferCapacity) {
    ringBuffer_ = std::make_unique<TelemetryRingBuffer>(ringBufferCapacity);
    initialized_.store(true);
}

void TelemetryInjector::Shutdown() {
    DisconnectFromBeaconBus();
    ringBuffer_.reset();
    initialized_.store(false);
}

void TelemetryInjector::InjectRejection(ViolationCode code,
                                        uint64_t intentId,
                                        uint64_t agentId,
                                        const std::string& explanation,
                                        const std::unordered_map<std::string, std::string>& context) {
    if (!initialized_.load() || !learningMode_.load()) return;
    
    RejectionFeedback feedback;
    static std::atomic<uint64_t> nextFeedbackId{1};
    feedback.feedbackId = nextFeedbackId.fetch_add(1);
    feedback.code = code;
    feedback.timestamp = GetTimestamp();
    feedback.intentId = intentId;
    feedback.agentId = agentId;
    feedback.explanation = explanation;
    feedback.metadata = context;
    
    // Try to extract from context
    auto it = context.find("intentType");
    if (it != context.end()) feedback.intentType = it->second;
    
    it = context.find("targetSymbol");
    if (it != context.end()) feedback.targetSymbol = it->second;
    
    it = context.find("targetFile");
    if (it != context.end()) feedback.targetFile = it->second;
    
    // Push to ring buffer
    ringBuffer_->PushRejection(feedback);
    
    // Notify subscribers
    NotifySubscribers(feedback);
    
    // Emit beacon
    BeaconEvent event;
    event.type = BeaconType::CUSTOM;
    event.sourceAgent = agentId;
    event.associatedIntent = intentId;
    event.metadata["type"] = "rejection_feedback";
    event.metadata["code"] = ViolationCodeToString(code);
    event.metadata["explanation"] = explanation;
    BEACON_BUS.Publish(std::move(event));
}

void TelemetryInjector::InjectRejectionFromFirewall(const std::string& intentType,
                                                     const std::string& targetSymbol,
                                                     ViolationCode code,
                                                     const std::string& reason) {
    std::unordered_map<std::string, std::string> context;
    context["intentType"] = intentType;
    context["targetSymbol"] = targetSymbol;
    context["source"] = "patch_firewall";
    
    InjectRejection(code, 0, 0, reason, context);
}

void TelemetryInjector::InjectSuccess(const SuccessFeedback& feedback) {
    if (!initialized_.load()) return;
    
    ringBuffer_->PushSuccess(feedback);
    
    // Emit beacon
    BeaconEvent event;
    event.type = BeaconType::CUSTOM;
    event.sourceAgent = feedback.agentId;
    event.associatedIntent = feedback.intentId;
    event.metadata["type"] = "success_feedback";
    event.metadata["intentType"] = feedback.intentType;
    event.metadata["executionTimeMs"] = std::to_string(feedback.executionTimeMs);
    BEACON_BUS.Publish(std::move(event));
}

void TelemetryInjector::InjectSuccessFromTransaction(uint64_t intentId,
                                                       const std::string& intentType,
                                                       double executionTimeMs) {
    SuccessFeedback feedback;
    static std::atomic<uint64_t> nextFeedbackId{1};
    feedback.feedbackId = nextFeedbackId.fetch_add(1);
    feedback.timestamp = GetTimestamp();
    feedback.intentId = intentId;
    feedback.agentId = 0; // TODO: Track agent
    feedback.intentType = intentType;
    feedback.executionTimeMs = executionTimeMs;
    feedback.testsPassed = true;
    feedback.testsCount = 0;
    feedback.securityScanPassed = true;
    feedback.performanceCheckPassed = true;
    
    InjectSuccess(feedback);
}

std::vector<RejectionFeedback> TelemetryInjector::GetRejectionHistoryForAgent(uint64_t agentId,
                                                                             size_t max) const {
    if (!ringBuffer_) return {};
    
    auto all = ringBuffer_->GetRecentRejections(max * 2); // Get extra to filter
    std::vector<RejectionFeedback> result;
    
    for (const auto& feedback : all) {
        if (feedback.agentId == agentId) {
            result.push_back(feedback);
            if (result.size() >= max) break;
        }
    }
    
    return result;
}

std::vector<RejectionFeedback> TelemetryInjector::GetRejectionHistoryForIntentType(
    const std::string& intentType, size_t max) const {
    if (!ringBuffer_) return {};
    
    auto all = ringBuffer_->GetRecentRejections(max * 2);
    std::vector<RejectionFeedback> result;
    
    for (const auto& feedback : all) {
        if (feedback.intentType == intentType) {
            result.push_back(feedback);
            if (result.size() >= max) break;
        }
    }
    
    return result;
}

std::string TelemetryInjector::GenerateModelContext(uint64_t agentId) const {
    std::stringstream ss;
    
    auto rejections = GetRejectionHistoryForAgent(agentId, 5);
    if (!rejections.empty()) {
        ss << "\n[RECENT REJECTIONS FOR THIS AGENT]\n";
        for (const auto& rej : rejections) {
            ss << rej.ToModelPrompt() << "\n\n";
        }
    }
    
    auto stats = GetStats();
    ss << "\n[AGENT PERFORMANCE METRICS]\n";
    ss << "Total Rejections: " << stats.totalRejections << "\n";
    ss << "Total Successes: " << stats.totalSuccesses << "\n";
    ss << "Success Rate: ";
    if (stats.totalRejections + stats.totalSuccesses > 0) {
        double rate = 100.0 * stats.totalSuccesses / 
                      (stats.totalSuccesses + stats.totalRejections);
        ss << rate << "%\n";
    } else {
        ss << "N/A\n";
    }
    
    return ss.str();
}

std::string TelemetryInjector::GenerateLearningSummary() const {
    auto stats = GetStats();
    
    std::stringstream ss;
    ss << "=== TELEMETRY LEARNING SUMMARY ===\n\n";
    
    ss << "Total Feedback Events: " << (stats.totalRejections + stats.totalSuccesses) << "\n";
    ss << "  - Rejections: " << stats.totalRejections << "\n";
    ss << "  - Successes: " << stats.totalSuccesses << "\n\n";
    
    if (stats.totalRejections > 0) {
        ss << "Top Rejection Reasons:\n";
        for (int i = 0; i < 256; ++i) {
            if (stats.rejectionsByCode[i] > 0) {
                ss << "  " << ViolationCodeToString(static_cast<ViolationCode>(i))
                   << ": " << stats.rejectionsByCode[i] << "\n";
            }
        }
        ss << "\n";
    }
    
    ss << "Average Execution Time: " << stats.averageExecutionTime << " ms\n";
    
    return ss.str();
}

uint64_t TelemetryInjector::SubscribeToRejections(FeedbackHandler handler) {
    std::lock_guard<std::mutex> lock(subscribersMutex_);
    uint64_t id = nextSubscriptionId_.fetch_add(1);
    subscribers_[id] = handler;
    return id;
}

void TelemetryInjector::Unsubscribe(uint64_t subscriptionId) {
    std::lock_guard<std::mutex> lock(subscribersMutex_);
    subscribers_.erase(subscriptionId);
}

void TelemetryInjector::ConnectToBeaconBus() {
    beaconSubscriptionId_ = BEACON_BUS.SubscribeAll(
        [this](const BeaconEvent& event) { OnBeaconEvent(event); }
    );
}

void TelemetryInjector::DisconnectFromBeaconBus() {
    if (beaconSubscriptionId_ != 0) {
        BEACON_BUS.Unsubscribe(beaconSubscriptionId_);
        beaconSubscriptionId_ = 0;
    }
}

TelemetryRingBuffer::Stats TelemetryInjector::GetStats() const {
    if (!ringBuffer_) return {};
    return ringBuffer_->GetStats();
}

std::string TelemetryInjector::GetStatsJson() const {
    auto stats = GetStats();
    
    std::stringstream ss;
    ss << "{";
    ss << "\"totalRejections\":" << stats.totalRejections << ",";
    ss << "\"totalSuccesses\":" << stats.totalSuccesses << ",";
    ss << "\"averageExecutionTime\":" << stats.averageExecutionTime << ",";
    ss << "\"lastRejectionTime\":" << stats.lastRejectionTime << ",";
    ss << "\"lastSuccessTime\":" << stats.lastSuccessTime;
    ss << "}";
    
    return ss.str();
}

void TelemetryInjector::NotifySubscribers(const RejectionFeedback& feedback) {
    std::lock_guard<std::mutex> lock(subscribersMutex_);
    for (const auto& [id, handler] : subscribers_) {
        handler(feedback);
    }
}

void TelemetryInjector::OnBeaconEvent(const BeaconEvent& event) {
    // Process relevant beacon events
    if (event.type == BeaconType::INTENT_FAILED) {
        auto it = event.metadata.find("reason");
        if (it != event.metadata.end()) {
            // Convert failure reason to rejection feedback
            std::unordered_map<std::string, std::string> context;
            context["beaconEvent"] = "INTENT_FAILED";
            context["reason"] = it->second;
            
            InjectRejection(ViolationCode::RUNTIME_CRASH,
                           event.associatedIntent,
                           event.sourceAgent,
                           "Intent failed: " + it->second,
                           context);
        }
    }
}

} // namespace Kernel
} // namespace RawrXD
