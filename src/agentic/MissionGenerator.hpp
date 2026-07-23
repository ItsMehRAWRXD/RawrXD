// ============================================================================
// MissionGenerator.hpp - Autonomous mission generation from binary profiles
// ============================================================================

#pragma once

#include "AgentTypes.hpp"
#include "Blackboard.hpp"
#include "KnowledgeGraph.hpp"
#include <vector>
#include <string>
#include <unordered_map>
#include <chrono>
#include <iostream>
#include <sstream>
#include <algorithm>

namespace RawrXD::Agentic {

// ============================================================================
// Binary Profile - extracted characteristics of a target binary
// ============================================================================

struct BinaryProfile {
    double entropy = 0.0;              // 0-8, higher = more random
    bool hasImports = false;
    int codeRegions = 0;
    int dataRegions = 0;
    bool hasDebugSymbols = false;
    bool hasPackingSignature = false;
    std::vector<std::string> suspiciousSections;
    std::vector<std::string> detectedLibraries;
    float executableSizeMB = 0.0f;
    std::string architecture;        // x86, x64, ARM, etc.
    std::string fileFormat;          // PE, ELF, Mach-O, etc.
    std::string compilerSignature;   // MSVC, GCC, Clang, etc.
    std::vector<std::string> detectedPackers;
    std::vector<std::string> detectedObfuscators;
    double importTableEntropy = 0.0;
    double codeSectionEntropy = 0.0;
    double dataSectionEntropy = 0.0;
    bool hasHighEntropyRegions = false;
    bool hasSuspiciousImports = false;
    bool hasAntiDebug = false;
    bool hasAntiVM = false;
    bool hasEncryptedStrings = false;
    size_t stringCount = 0;
    size_t functionCount = 0;
    
    // Risk score calculation
    double calculateRiskScore() const {
        double score = 0.0;
        if (hasPackingSignature) score += 0.3;
        if (hasHighEntropyRegions) score += 0.2;
        if (hasAntiDebug || hasAntiVM) score += 0.2;
        if (hasSuspiciousImports) score += 0.15;
        if (!detectedPackers.empty()) score += 0.1 * detectedPackers.size();
        if (!detectedObfuscators.empty()) score += 0.1 * detectedObfuscators.size();
        if (entropy > 7.0) score += 0.15;
        return std::min(1.0, score);
    }
    
    // Analysis value - how much can we learn from this binary
    double calculateAnalysisValue() const {
        double value = 0.5; // Base value
        if (hasImports) value += 0.1;
        if (codeRegions > 0) value += 0.1;
        if (functionCount > 0) value += 0.1;
        if (stringCount > 0) value += 0.05;
        if (!compilerSignature.empty()) value += 0.1;
        if (!architecture.empty()) value += 0.05;
        return std::min(1.0, value);
    }
    
    // Generate a signature for workflow matching
    std::string generateSignature() const {
        std::ostringstream oss;
        oss << fileFormat << "_" << architecture;
        if (hasPackingSignature) oss << "_packed";
        if (hasHighEntropyRegions) oss << "_highentropy";
        if (hasAntiDebug) oss << "_antidebug";
        return oss.str();
    }
};

// ============================================================================
// Mission Priority
// ============================================================================

enum class MissionPriority {
    CRITICAL = 0,   // Must execute immediately
    HIGH = 1,       // Important for mission success
    MEDIUM = 2,     // Standard analysis
    LOW = 3,        // Nice to have
    BACKGROUND = 4  // Can run opportunistically
};

struct GeneratedMission {
    std::string id;
    std::string description;
    std::string missionType;
    MissionPriority priority;
    std::vector<std::string> requiredCapabilities;
    std::vector<std::string> prerequisites; // Mission IDs that must complete first
    std::vector<std::string> subMissions;
    std::string targetSignature;
    double estimatedConfidence = 0.0;
    std::chrono::milliseconds estimatedDuration{0};
    std::chrono::steady_clock::time_point created;
    bool completed = false;
    bool successful = false;
    
    // Convert to AgentGoal for execution
    AgentGoal toAgentGoal() const {
        AgentGoal goal;
        goal.description = description;
        goal.priority = static_cast<double>(priority) / 4.0; // Normalize to 0-1
        goal.success_criteria = {"Complete " + missionType};
        goal.is_critical = (priority == MissionPriority::CRITICAL);
        return goal;
    }
};

// ============================================================================
// Mission Generator - produces missions autonomously from binary profiles
// ============================================================================

class MissionGenerator {
public:
    MissionGenerator() = default;
    ~MissionGenerator() = default;
    
    // Generate missions from binary profile
    std::vector<GeneratedMission> generateMissions(const BinaryProfile& profile);
    
    // Generate missions with knowledge graph context
    std::vector<GeneratedMission> generateMissions(
        const BinaryProfile& profile,
        const KnowledgeGraph& knowledge);
    
    // Calculate priority for a mission
    MissionPriority calculatePriority(const GeneratedMission& mission, 
                                       const BinaryProfile& profile) const;
    
    // Dynamic mission expansion - add sub-missions based on progress
    std::vector<GeneratedMission> expandMissions(
        const GeneratedMission& current,
        const BinaryProfile& profile,
        const std::vector<AgentObservation>& evidence);
    
    // Generate follow-up missions from completed mission results
    std::vector<GeneratedMission> generateFollowUpMissions(
        const GeneratedMission& completed,
        const AgentResult& result,
        const BinaryProfile& profile);
    
    // Get metrics
    struct GeneratorMetrics {
        int totalMissionsGenerated = 0;
        int missionsExpanded = 0;
        int followUpMissionsGenerated = 0;
        std::unordered_map<std::string, int> missionsByType;
        double averagePriority = 0.0;
    };
    GeneratorMetrics getMetrics() const { return metrics_; }
    void resetMetrics() { metrics_ = {}; }
    
private:
    GeneratorMetrics metrics_;
    int missionCounter_ = 0;
    
    // Mission template creators
    GeneratedMission createPackerDetectionMission(const BinaryProfile& profile);
    GeneratedMission createUnpackingMission(const BinaryProfile& profile);
    GeneratedMission createImportMappingMission(const BinaryProfile& profile);
    GeneratedMission createCFGRecoveryMission(const BinaryProfile& profile);
    GeneratedMission createFunctionClassificationMission(const BinaryProfile& profile);
    GeneratedMission createStringExtractionMission(const BinaryProfile& profile);
    GeneratedMission createEntropyAnalysisMission(const BinaryProfile& profile);
    GeneratedMission createAntiDebugDetectionMission(const BinaryProfile& profile);
    GeneratedMission createSymbolRecoveryMission(const BinaryProfile& profile);
    GeneratedMission createYARAScanMission(const BinaryProfile& profile);
    GeneratedMission createReportGenerationMission(const BinaryProfile& profile);
    
    // Sub-mission generation
    std::vector<GeneratedMission> generateSubMissions(
        const GeneratedMission& parent,
        const BinaryProfile& profile);
    
    // Utility
    std::string generateMissionId(const std::string& type);
    double estimateConfidence(const std::string& missionType, const BinaryProfile& profile);
    std::chrono::milliseconds estimateDuration(const std::string& missionType, const BinaryProfile& profile);
};

} // namespace RawrXD::Agentic
