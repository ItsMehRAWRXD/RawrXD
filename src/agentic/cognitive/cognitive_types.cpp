/**
 * @file cognitive_types.cpp
 * @brief Implementation of cognitive type utilities
 */

#include "cognitive_types.hpp"
#include <sstream>
#include <iomanip>
#include <random>

namespace rawrxd::cognitive {

// ============================================================================
// Mission Type Conversions
// ============================================================================

std::string MissionTypeToString(MissionType type) {
    switch (type) {
        case MissionType::EXTRACT_C2: return "EXTRACT_C2";
        case MissionType::IDENTIFY_MALWARE: return "IDENTIFY_MALWARE";
        case MissionType::REVERSE_PROTOCOL: return "REVERSE_PROTOCOL";
        case MissionType::FIND_VULNERABILITY: return "FIND_VULNERABILITY";
        case MissionType::UNPACK_BINARY: return "UNPACK_BINARY";
        case MissionType::ANALYZE_CRYPTO: return "ANALYZE_CRYPTO";
        case MissionType::TRACE_EXECUTION: return "TRACE_EXECUTION";
        case MissionType::EXFILTRATION_PATTERN: return "EXFILTRATION_PATTERN";
        case MissionType::GENERIC_ANALYSIS: return "GENERIC_ANALYSIS";
        case MissionType::CUSTOM: return "CUSTOM";
        default: return "UNKNOWN";
    }
}

MissionType StringToMissionType(const std::string& str) {
    if (str == "EXTRACT_C2") return MissionType::EXTRACT_C2;
    if (str == "IDENTIFY_MALWARE") return MissionType::IDENTIFY_MALWARE;
    if (str == "REVERSE_PROTOCOL") return MissionType::REVERSE_PROTOCOL;
    if (str == "FIND_VULNERABILITY") return MissionType::FIND_VULNERABILITY;
    if (str == "UNPACK_BINARY") return MissionType::UNPACK_BINARY;
    if (str == "ANALYZE_CRYPTO") return MissionType::ANALYZE_CRYPTO;
    if (str == "TRACE_EXECUTION") return MissionType::TRACE_EXECUTION;
    if (str == "EXFILTRATION_PATTERN") return MissionType::EXFILTRATION_PATTERN;
    if (str == "CUSTOM") return MissionType::CUSTOM;
    return MissionType::GENERIC_ANALYSIS;
}

// ============================================================================
// Status Conversions
// ============================================================================

std::string StatusToString(SubGoal::Status status) {
    switch (status) {
        case SubGoal::Status::PENDING: return "PENDING";
        case SubGoal::Status::IN_PROGRESS: return "IN_PROGRESS";
        case SubGoal::Status::COMPLETE: return "COMPLETE";
        case SubGoal::Status::FAILED: return "FAILED";
        case SubGoal::Status::BLOCKED: return "BLOCKED";
        case SubGoal::Status::CANCELLED: return "CANCELLED";
        default: return "UNKNOWN";
    }
}

std::string StatusToString(Hypothesis::Status status) {
    switch (status) {
        case Hypothesis::Status::UNVERIFIED: return "UNVERIFIED";
        case Hypothesis::Status::UNDER_TEST: return "UNDER_TEST";
        case Hypothesis::Status::CONFIRMED: return "CONFIRMED";
        case Hypothesis::Status::REFUTED: return "REFUTED";
        case Hypothesis::Status::MUTATED: return "MUTATED";
        case Hypothesis::Status::DEPRECATED: return "DEPRECATED";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// UUID Generation
// ============================================================================

std::string GenerateUUID() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint64_t> dis(0, 0xFFFFFFFFFFFFFFFF);
    
    uint64_t high = dis(gen);
    uint64_t low = dis(gen);
    
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    oss << std::setw(8) << (high >> 32) << "-";
    oss << std::setw(4) << ((high >> 16) & 0xFFFF) << "-";
    oss << std::setw(4) << (high & 0xFFFF) << "-";
    oss << std::setw(4) << ((low >> 48) & 0xFFFF) << "-";
    oss << std::setw(12) << (low & 0xFFFFFFFFFFFF);
    
    return oss.str();
}

// ============================================================================
// Confidence Aggregation
// ============================================================================

Confidence AggregateConfidence(const std::vector<std::string>& evidence_ids,
                                const std::unordered_map<std::string, Evidence>& evidence_pool) {
    if (evidence_ids.empty()) return 0.0f;
    
    float total_weight = 0.0f;
    float weighted_sum = 0.0f;
    
    for (const auto& id : evidence_ids) {
        auto it = evidence_pool.find(id);
        if (it != evidence_pool.end()) {
            const Evidence& ev = it->second;
            float w = std::abs(ev.weight);
            total_weight += w;
            weighted_sum += ev.confidence * ev.weight;
        }
    }
    
    if (total_weight == 0.0f) return 0.0f;
    
    // Normalize to [0, 1]
    float result = (weighted_sum / total_weight + 1.0f) / 2.0f;
    return std::clamp(result, 0.0f, 1.0f);
}

} // namespace rawrxd::cognitive
