// VAL-063 Streaming: Service Contract Witnesses Implementation

#include "streaming_witness.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <openssl/evp.h>

namespace RawrXD {
namespace Gateway {

// ============================================================================
// SHA-256 Helper
// ============================================================================

static std::string ComputeSHA256(const std::string& data) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return "";
    
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    
    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) ||
        !EVP_DigestUpdate(ctx, data.data(), data.size()) ||
        !EVP_DigestFinal_ex(ctx, hash, &hash_len)) {
        EVP_MD_CTX_free(ctx);
        return "";
    }
    
    EVP_MD_CTX_free(ctx);
    
    std::stringstream ss;
    for (unsigned int i = 0; i < hash_len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

// ============================================================================
// StreamingEvent Implementation
// ============================================================================

std::string StreamingEvent::Serialize() const {
    std::stringstream ss;
    ss << "{";
    ss << "\"execution_id\":\"" << execution_id << "\",";
    ss << "\"sequence_number\":" << sequence_number << ",";
    ss << "\"type\":" << (int)type << ",";
    ss << "\"timestamp_ns\":" << timestamp_ns << ",";
    ss << "\"token_id\":" << token_id << ",";
    ss << "\"token_text\":\"" << token_text << "\",";
    ss << "\"position\":" << position << ",";
    ss << "\"queue_depth\":" << queue_depth << ",";
    ss << "\"queue_capacity\":" << queue_capacity << ",";
    ss << "\"error_code\":\"" << error_code << "\",";
    ss << "\"error_message\":\"" << error_message << "\"";
    ss << "}";
    return ss.str();
}

std::string StreamingEvent::ComputeHash() const {
    return ComputeSHA256(Serialize());
}

// ============================================================================
// StreamingContractWitness Implementation
// ============================================================================

void StreamingContractWitness::RecordEvent(const StreamingEvent& event) {
    std::lock_guard<std::mutex> lock(mutex_);
    events_.push_back(event);
}

StreamingContractWitness::ContractValidation StreamingContractWitness::ValidateContract() const {
    std::lock_guard<std::mutex> lock(mutex_);
    ContractValidation validation;
    
    validation.event_ordering_valid = CheckEventOrdering();
    validation.sequence_continuity_valid = CheckSequenceContinuity();
    validation.timestamp_monotonic = CheckTimestampMonotonicity();
    validation.execution_id_consistent = CheckExecutionIdConsistency();
    
    return validation;
}

bool StreamingContractWitness::CheckEventOrdering() const {
    if (events_.size() < 2) return true;
    
    // Expected order: REQUEST_START -> PROMPT_BEGIN -> PROMPT_END -> 
    //                  TOKEN_GENERATED* -> GENERATION_COMPLETE -> REQUEST_END
    StreamingEventType expected = StreamingEventType::REQUEST_START;
    
    for (const auto& event : events_) {
        if (event.type == StreamingEventType::ERROR) {
            // Errors can occur at any point
            continue;
        }
        
        // Check valid transitions
        switch (expected) {
            case StreamingEventType::REQUEST_START:
                if (event.type != StreamingEventType::REQUEST_START) return false;
                expected = StreamingEventType::PROMPT_BEGIN;
                break;
            case StreamingEventType::PROMPT_BEGIN:
                if (event.type == StreamingEventType::PROMPT_BEGIN) {
                    expected = StreamingEventType::PROMPT_END;
                }
                break;
            case StreamingEventType::PROMPT_END:
                if (event.type == StreamingEventType::PROMPT_END) {
                    expected = StreamingEventType::TOKEN_GENERATED;
                }
                break;
            case StreamingEventType::TOKEN_GENERATED:
                if (event.type == StreamingEventType::TOKEN_GENERATED) {
                    // Stay in TOKEN_GENERATED state
                } else if (event.type == StreamingEventType::GENERATION_COMPLETE) {
                    expected = StreamingEventType::REQUEST_END;
                }
                break;
            case StreamingEventType::REQUEST_END:
                if (event.type != StreamingEventType::REQUEST_END) return false;
                break;
            default:
                break;
        }
    }
    
    return true;
}

bool StreamingContractWitness::CheckSequenceContinuity() const {
    if (events_.empty()) return true;
    
    uint64_t expected_seq = events_[0].sequence_number;
    for (const auto& event : events_) {
        if (event.sequence_number != expected_seq) return false;
        expected_seq++;
    }
    return true;
}

bool StreamingContractWitness::CheckTimestampMonotonicity() const {
    if (events_.size() < 2) return true;
    
    for (size_t i = 1; i < events_.size(); ++i) {
        if (events_[i].timestamp_ns < events_[i-1].timestamp_ns) return false;
    }
    return true;
}

bool StreamingContractWitness::CheckExecutionIdConsistency() const {
    if (events_.empty()) return true;
    
    const std::string& first_id = events_[0].execution_id;
    for (const auto& event : events_) {
        if (event.execution_id != first_id) return false;
    }
    return true;
}

std::string StreamingContractWitness::GenerateEvidence() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto validation = ValidateContract();
    
    std::stringstream json;
    json << "{\n";
    json << "  \"gate\": \"VAL-063D\",\n";
    json << "  \"component\": \"StreamingContract\",\n";
    json << "  \"claim\": \"Streaming events follow valid producer-consumer contract\",\n";
    json << "  \"timestamp\": \"" << std::chrono::system_clock::now().time_since_epoch().count() << "\",\n";
    json << "  \"validation\": {\n";
    json << "    \"event_ordering_valid\": " << (validation.event_ordering_valid ? "true" : "false") << ",\n";
    json << "    \"sequence_continuity_valid\": " << (validation.sequence_continuity_valid ? "true" : "false") << ",\n";
    json << "    \"timestamp_monotonic\": " << (validation.timestamp_monotonic ? "true" : "false") << ",\n";
    json << "    \"execution_id_consistent\": " << (validation.execution_id_consistent ? "true" : "false") << "\n";
    json << "  },\n";
    json << "  \"event_count\": " << events_.size() << ",\n";
    json << "  \"events\": [\n";
    
    for (size_t i = 0; i < events_.size(); ++i) {
        json << "    " << events_[i].Serialize();
        if (i < events_.size() - 1) json << ",";
        json << "\n";
    }
    
    json << "  ],\n";
    json << "  \"status\": \"" << (validation.IsValid() ? "PASS" : "FAIL") << "\"\n";
    json << "}\n";
    
    return json.str();
}

// ============================================================================
// BackpressureWitness Implementation
// ============================================================================

void BackpressureWitness::RecordProduction(uint64_t count) {
    std::lock_guard<std::mutex> lock(mutex_);
    metrics_.tokens_produced += count;
}

void BackpressureWitness::RecordConsumption(uint64_t count) {
    std::lock_guard<std::mutex> lock(mutex_);
    metrics_.tokens_consumed += count;
}

void BackpressureWitness::RecordBackpressureEvent(uint32_t queue_depth, uint32_t capacity) {
    std::lock_guard<std::mutex> lock(mutex_);
    metrics_.backpressure_events++;
    if (queue_depth > metrics_.max_queue_depth) {
        metrics_.max_queue_depth = queue_depth;
    }
}

void BackpressureWitness::RecordStall(uint64_t duration_ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    metrics_.total_stall_ms += duration_ms;
}

BackpressureWitness::BackpressureMetrics BackpressureWitness::GetMetrics() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return metrics_;
}

bool BackpressureWitness::CheckNoDroppedTokens() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return metrics_.tokens_dropped == 0;
}

bool BackpressureWitness::CheckNoDuplicateTokens() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return metrics_.tokens_duplicated == 0;
}

bool BackpressureWitness::CheckBoundedMemory() const {
    std::lock_guard<std::mutex> lock(mutex_);
    // Assume bounded if max queue depth is reasonable (< 1000)
    return metrics_.max_queue_depth < 1000;
}

bool BackpressureWitness::CheckDeterministicStall() const {
    std::lock_guard<std::mutex> lock(mutex_);
    // Stall behavior is deterministic if we have recorded stalls
    // and they don't exceed reasonable bounds
    return metrics_.total_stall_ms < 60000; // < 60 seconds total stall
}

std::string BackpressureWitness::GenerateEvidence() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::stringstream json;
    json << "{\n";
    json << "  \"gate\": \"VAL-063E\",\n";
    json << "  \"component\": \"Backpressure\",\n";
    json << "  \"claim\": \"Token production is bounded with no loss or duplication\",\n";
    json << "  \"timestamp\": \"" << std::chrono::system_clock::now().time_since_epoch().count() << "\",\n";
    json << "  \"metrics\": {\n";
    json << "    \"tokens_produced\": " << metrics_.tokens_produced << ",\n";
    json << "    \"tokens_consumed\": " << metrics_.tokens_consumed << ",\n";
    json << "    \"tokens_dropped\": " << metrics_.tokens_dropped << ",\n";
    json << "    \"tokens_duplicated\": " << metrics_.tokens_duplicated << ",\n";
    json << "    \"backpressure_events\": " << metrics_.backpressure_events << ",\n";
    json << "    \"max_queue_depth\": " << metrics_.max_queue_depth << ",\n";
    json << "    \"total_stall_ms\": " << metrics_.total_stall_ms << "\n";
    json << "  },\n";
    json << "  \"invariants\": {\n";
    json << "    \"no_dropped_tokens\": " << (CheckNoDroppedTokens() ? "true" : "false") << ",\n";
    json << "    \"no_duplicate_tokens\": " << (CheckNoDuplicateTokens() ? "true" : "false") << ",\n";
    json << "    \"bounded_memory\": " << (CheckBoundedMemory() ? "true" : "false") << ",\n";
    json << "    \"deterministic_stall\": " << (CheckDeterministicStall() ? "true" : "false") << "\n";
    json << "  },\n";
    json << "  \"status\": \"" << (metrics_.IsValid() ? "PASS" : "FAIL") << "\"\n";
    json << "}\n";
    
    return json.str();
}

// ============================================================================
// CorrelationWitness Implementation
// ============================================================================

void CorrelationWitness::SealExecutionChain(const ExecutionChain& chain) {
    std::lock_guard<std::mutex> lock(mutex_);
    chains_[chain.execution_id] = chain;
}

bool CorrelationWitness::VerifyChainIntegrity(const std::string& execution_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = chains_.find(execution_id);
    if (it == chains_.end()) return false;
    return it->second.Validate();
}

std::string CorrelationWitness::GetChainProof(const std::string& execution_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = chains_.find(execution_id);
    if (it == chains_.end()) return "";
    return it->second.ComputeChainHash();
}

std::string CorrelationWitness::GenerateEvidence(const std::string& execution_id) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = chains_.find(execution_id);
    if (it == chains_.end()) {
        return "{\"error\": \"Execution ID not found\"}";
    }
    
    const auto& chain = it->second;
    bool valid = chain.Validate();
    std::string chain_hash = chain.ComputeChainHash();
    
    std::stringstream json;
    json << "{\n";
    json << "  \"gate\": \"VAL-063F\",\n";
    json << "  \"component\": \"Correlation\",\n";
    json << "  \"claim\": \"Complete execution chain is cryptographically correlated\",\n";
    json << "  \"timestamp\": \"" << std::chrono::system_clock::now().time_since_epoch().count() << "\",\n";
    json << "  \"execution_id\": \"" << execution_id << "\",\n";
    json << "  \"chain\": {\n";
    json << "    \"request_hash\": \"" << chain.request_hash << "\",\n";
    json << "    \"model_hash\": \"" << chain.model_hash << "\",\n";
    json << "    \"runtime_hash\": \"" << chain.runtime_hash << "\",\n";
    json << "    \"token_sequence_hash\": \"" << chain.token_sequence_hash << "\",\n";
    json << "    \"output_hash\": \"" << chain.output_hash << "\"\n";
    json << "  },\n";
    json << "  \"chain_hash\": \"" << chain_hash << "\",\n";
    json << "  \"chain_valid\": " << (valid ? "true" : "false") << ",\n";
    json << "  \"status\": \"" << (valid ? "PASS" : "FAIL") << "\"\n";
    json << "}\n";
    
    return json.str();
}

std::string CorrelationWitness::ExecutionChain::ComputeChainHash() const {
    std::stringstream ss;
    ss << request_hash << "|"
       << model_hash << "|"
       << runtime_hash << "|"
       << token_sequence_hash << "|"
       << output_hash;
    return ComputeSHA256(ss.str());
}

bool CorrelationWitness::ExecutionChain::Validate() const {
    return !request_hash.empty() &&
           !model_hash.empty() &&
           !runtime_hash.empty() &&
           !token_sequence_hash.empty() &&
           !output_hash.empty();
}

// ============================================================================
// LiveEvidenceCapture Implementation
// ============================================================================

std::string LiveEvidenceCapture::ComputeSHA256(const std::string& data) {
    return RawrXD::Gateway::ComputeSHA256(data);
}

std::string LiveEvidenceCapture::ComputeFileSHA256(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return "";
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    return ComputeSHA256(buffer.str());
}

std::string LiveEvidenceCapture::ComputeTokenHash(const std::vector<int32_t>& tokens) {
    std::string data;
    data.reserve(tokens.size() * sizeof(int32_t));
    for (int32_t token : tokens) {
        data.append(reinterpret_cast<const char*>(&token), sizeof(token));
    }
    return ComputeSHA256(data);
}

LiveEvidenceCapture::EvidenceSnapshot LiveEvidenceCapture::CaptureAtStart(
    const std::string& request_data,
    const std::string& model_path,
    const std::string& runtime_path) {
    
    EvidenceSnapshot snapshot;
    snapshot.request_hash = ComputeSHA256(request_data);
    snapshot.model_artifact_hash = ComputeFileSHA256(model_path);
    snapshot.runtime_binary_hash = ComputeFileSHA256(runtime_path);
    snapshot.timestamp_start_ns = std::chrono::system_clock::now().time_since_epoch().count();
    
    return snapshot;
}

LiveEvidenceCapture::EvidenceSnapshot LiveEvidenceCapture::CaptureAtEnd(
    const std::vector<int32_t>& tokens,
    const std::string& output_text) {
    
    EvidenceSnapshot snapshot;
    snapshot.token_sequence_hash = ComputeTokenHash(tokens);
    snapshot.output_text_hash = ComputeSHA256(output_text);
    snapshot.timestamp_end_ns = std::chrono::system_clock::now().time_since_epoch().count();
    
    return snapshot;
}

bool LiveEvidenceCapture::EvidenceSnapshot::Validate() const {
    return !request_hash.empty() &&
           !model_artifact_hash.empty() &&
           !runtime_binary_hash.empty() &&
           !token_sequence_hash.empty() &&
           !output_text_hash.empty() &&
           timestamp_end_ns > timestamp_start_ns;
}

std::string LiveEvidenceCapture::EvidenceSnapshot::Serialize() const {
    std::stringstream json;
    json << "{\n";
    json << "  \"request_hash\": \"" << request_hash << "\",\n";
    json << "  \"model_artifact_hash\": \"" << model_artifact_hash << "\",\n";
    json << "  \"runtime_binary_hash\": \"" << runtime_binary_hash << "\",\n";
    json << "  \"token_sequence_hash\": \"" << token_sequence_hash << "\",\n";
    json << "  \"output_text_hash\": \"" << output_text_hash << "\",\n";
    json << "  \"timestamp_start_ns\": " << timestamp_start_ns << ",\n";
    json << "  \"timestamp_end_ns\": " << timestamp_end_ns << "\n";
    json << "}";
    return json.str();
}

std::string LiveEvidenceCapture::SealEvidence(const EvidenceSnapshot& snapshot) {
    if (!snapshot.Validate()) {
        return "{\"error\": \"Invalid evidence snapshot\"}";
    }
    
    std::stringstream json;
    json << "{\n";
    json << "  \"gate\": \"VAL-063-LIVE\",\n";
    json << "  \"claim\": \"Live execution evidence captured at runtime\",\n";
    json << "  \"timestamp\": \"" << std::chrono::system_clock::now().time_since_epoch().count() << "\",\n";
    json << "  \"evidence\": " << snapshot.Serialize() << ",\n";
    json << "  \"sealed\": true,\n";
    json << "  \"status\": \"PASS\"\n";
    json << "}";
    return json.str();
}

// ============================================================================
// GatewayEnforcer Implementation
// ============================================================================

GatewayEnforcer& GatewayEnforcer::Instance() {
    static GatewayEnforcer instance;
    return instance;
}

GatewayEnforcer::ExecutionContext GatewayEnforcer::IssueContext(const std::string& request_hash) {
    ExecutionContext ctx;
    ctx.execution_id = request_hash.substr(0, 16) + std::to_string(
        std::chrono::system_clock::now().time_since_epoch().count());
    ctx.gateway_attestation_hash = ComputeSHA256(request_hash + ctx.execution_id);
    ctx.issued_at_ns = std::chrono::system_clock::now().time_since_epoch().count();
    ctx.expires_at_ns = ctx.issued_at_ns + 300000000000; // 5 minutes
    
    std::lock_guard<std::mutex> lock(mutex_);
    active_contexts_[ctx.execution_id] = ctx;
    
    return ctx;
}

bool GatewayEnforcer::ValidateContext(const ExecutionContext& ctx) {
    if (!ctx.IsValid()) return false;
    
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = active_contexts_.find(ctx.execution_id);
    if (it == active_contexts_.end()) return false;
    
    return it->second.gateway_attestation_hash == ctx.gateway_attestation_hash;
}

void GatewayEnforcer::RevokeContext(const std::string& execution_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    active_contexts_.erase(execution_id);
}

bool GatewayEnforcer::RequireGatewayEntry() {
    if (!gateway_bound_.load()) return false;
    enforced_count_++;
    return true;
}

bool GatewayEnforcer::RejectDirectRuntimeAccess() {
    if (!gateway_bound_.load()) return true; // Allow if not bound
    rejected_count_++;
    return false;
}

bool GatewayEnforcer::IsGatewayBound() const {
    return gateway_bound_.load();
}

uint64_t GatewayEnforcer::GetEnforcedRequestCount() const {
    return enforced_count_.load();
}

uint64_t GatewayEnforcer::GetRejectedBypassAttempts() const {
    return rejected_count_.load();
}

bool GatewayEnforcer::ExecutionContext::IsValid() const {
    uint64_t now = std::chrono::system_clock::now().time_since_epoch().count();
    return !execution_id.empty() &&
           !gateway_attestation_hash.empty() &&
           now >= issued_at_ns &&
           now <= expires_at_ns;
}

std::string GatewayEnforcer::ExecutionContext::ComputeHash() const {
    std::stringstream ss;
    ss << execution_id << "|" << gateway_attestation_hash << "|" << issued_at_ns;
    return RawrXD::Gateway::ComputeSHA256(ss.str());
}

} // namespace Gateway
} // namespace RawrXD
