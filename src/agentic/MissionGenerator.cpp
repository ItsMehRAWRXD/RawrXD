// ============================================================================
// MissionGenerator.cpp - Autonomous mission generation implementation
// ============================================================================

#include "MissionGenerator.hpp"

namespace RawrXD::Agentic {

// ============================================================================
// Main Generation Logic
// ============================================================================

std::vector<GeneratedMission> MissionGenerator::generateMissions(const BinaryProfile& profile) {
    std::vector<GeneratedMission> missions;
    
    std::cout << "[MissionGenerator] Analyzing binary profile...\n";
    std::cout << "  Entropy: " << profile.entropy << "\n";
    std::cout << "  Risk Score: " << profile.calculateRiskScore() << "\n";
    std::cout << "  Analysis Value: " << profile.calculateAnalysisValue() << "\n";
    
    // Always generate entropy analysis first
    missions.push_back(createEntropyAnalysisMission(profile));
    
    // Generate packer detection if entropy is high
    if (profile.entropy > 6.5 || profile.hasHighEntropyRegions || profile.hasPackingSignature) {
        missions.push_back(createPackerDetectionMission(profile));
        
        // If packed, add unpacking mission
        if (profile.hasPackingSignature || !profile.detectedPackers.empty()) {
            auto unpack = createUnpackingMission(profile);
            unpack.prerequisites.push_back(missions.back().id);
            missions.push_back(unpack);
        }
    }
    
    // Generate import mapping if imports exist
    if (profile.hasImports) {
        missions.push_back(createImportMappingMission(profile));
    }
    
    // Generate anti-debug detection if suspicious
    if (profile.hasAntiDebug || profile.hasAntiVM) {
        missions.push_back(createAntiDebugDetectionMission(profile));
    }
    
    // Generate CFG recovery if code regions exist
    if (profile.codeRegions > 0) {
        auto cfg = createCFGRecoveryMission(profile);
        // CFG recovery depends on unpacking if packed
        if (profile.hasPackingSignature) {
            for (const auto& m : missions) {
                if (m.missionType == "unpacking") {
                    cfg.prerequisites.push_back(m.id);
                }
            }
        }
        missions.push_back(cfg);
        
        // Function classification depends on CFG
        auto classify = createFunctionClassificationMission(profile);
        classify.prerequisites.push_back(cfg.id);
        missions.push_back(classify);
    }
    
    // Generate string extraction
    if (profile.stringCount > 0 || profile.hasEncryptedStrings) {
        missions.push_back(createStringExtractionMission(profile));
    }
    
    // Generate YARA scan
    missions.push_back(createYARAScanMission(profile));
    
    // Generate symbol recovery if debug symbols present
    if (profile.hasDebugSymbols) {
        missions.push_back(createSymbolRecoveryMission(profile));
    }
    
    // Always generate final report
    auto report = createReportGenerationMission(profile);
    // Report depends on all other missions
    for (const auto& m : missions) {
        if (m.missionType != "report") {
            report.prerequisites.push_back(m.id);
        }
    }
    missions.push_back(report);
    
    // Calculate priorities
    for (auto& mission : missions) {
        mission.priority = calculatePriority(mission, profile);
    }
    
    // Sort by priority (lower number = higher priority)
    std::sort(missions.begin(), missions.end(), 
        [](const GeneratedMission& a, const GeneratedMission& b) {
            return static_cast<int>(a.priority) < static_cast<int>(b.priority);
        });
    
    metrics_.totalMissionsGenerated += missions.size();
    for (const auto& m : missions) {
        metrics_.missionsByType[m.missionType]++;
    }
    
    std::cout << "[MissionGenerator] Generated " << missions.size() << " missions\n";
    
    return missions;
}

std::vector<GeneratedMission> MissionGenerator::generateMissions(
    const BinaryProfile& profile,
    const KnowledgeGraph& knowledge) {
    
    auto missions = generateMissions(profile);
    
    // Query knowledge graph for similar binaries
    auto knownPackers = knowledge.getByCategory("packers");
    auto knownObfuscators = knowledge.getByCategory("obfuscation_styles");
    
    // Adjust priorities based on known patterns
    for (auto& mission : missions) {
        if (mission.missionType == "packer_detection") {
            for (const auto& entry : knownPackers) {
                if (entry.confidence > 0.7) {
                    // Boost priority if we know about this packer
                    mission.priority = MissionPriority::HIGH;
                }
            }
        }
    }
    
    return missions;
}

MissionPriority MissionGenerator::calculatePriority(
    const GeneratedMission& mission,
    const BinaryProfile& profile) const {
    
    // Base priority from mission type
    if (mission.missionType == "entropy_analysis") return MissionPriority::CRITICAL;
    if (mission.missionType == "packer_detection") return MissionPriority::HIGH;
    if (mission.missionType == "unpacking") return MissionPriority::HIGH;
    if (mission.missionType == "anti_debug_detection") return MissionPriority::HIGH;
    if (mission.missionType == "import_mapping") return MissionPriority::MEDIUM;
    if (mission.missionType == "cfg_recovery") return MissionPriority::MEDIUM;
    if (mission.missionType == "function_classification") return MissionPriority::LOW;
    if (mission.missionType == "string_extraction") return MissionPriority::LOW;
    if (mission.missionType == "yara_scan") return MissionPriority::MEDIUM;
    if (mission.missionType == "symbol_recovery") return MissionPriority::LOW;
    if (mission.missionType == "report") return MissionPriority::BACKGROUND;
    
    return MissionPriority::MEDIUM;
}

std::vector<GeneratedMission> MissionGenerator::expandMissions(
    const GeneratedMission& current,
    const BinaryProfile& profile,
    const std::vector<AgentObservation>& evidence) {
    
    std::vector<GeneratedMission> expanded;
    
    // Check evidence for new indicators
    for (const auto& obs : evidence) {
        if (obs.data.count("entropy")) {
            double entropy = std::stod(obs.data.at("entropy"));
            if (entropy > 7.0 && current.missionType != "unpacking") {
                // High entropy found - add unpacking if not already planned
                auto unpack = createUnpackingMission(profile);
                unpack.prerequisites.push_back(current.id);
                expanded.push_back(unpack);
            }
        }
        
        if (obs.data.count("packed") && obs.data.at("packed") == "true") {
            // Binary is packed - ensure unpacking is in plan
            bool hasUnpacking = false;
            for (const auto& m : expanded) {
                if (m.missionType == "unpacking") hasUnpacking = true;
            }
            if (!hasUnpacking) {
                auto unpack = createUnpackingMission(profile);
                unpack.prerequisites.push_back(current.id);
                expanded.push_back(unpack);
            }
        }
        
        if (obs.data.count("anti_debug") && obs.data.at("anti_debug") == "true") {
            auto antiDebug = createAntiDebugDetectionMission(profile);
            antiDebug.prerequisites.push_back(current.id);
            expanded.push_back(antiDebug);
        }
    }
    
    metrics_.missionsExpanded += expanded.size();
    
    return expanded;
}

std::vector<GeneratedMission> MissionGenerator::generateFollowUpMissions(
    const GeneratedMission& completed,
    const AgentResult& result,
    const BinaryProfile& profile) {
    
    std::vector<GeneratedMission> followUps;
    
    if (!result.success) {
        // Mission failed - generate retry with different approach
        auto retry = completed;
        retry.id = generateMissionId(completed.missionType + "_retry");
        retry.description = "Retry: " + completed.description;
        retry.priority = MissionPriority::HIGH;
        followUps.push_back(retry);
    }
    
    if (result.confidence < 0.5 && result.success) {
        // Low confidence - generate validation mission
        auto validate = createReportGenerationMission(profile);
        validate.id = generateMissionId("validation");
        validate.description = "Validate: " + completed.description;
        validate.prerequisites.push_back(completed.id);
        validate.priority = MissionPriority::HIGH;
        followUps.push_back(validate);
    }
    
    // Mission-specific follow-ups
    if (completed.missionType == "packer_detection" && result.success) {
        // If packer detected, ensure unpacking follows
        auto unpack = createUnpackingMission(profile);
        unpack.prerequisites.push_back(completed.id);
        followUps.push_back(unpack);
    }
    
    if (completed.missionType == "cfg_recovery" && result.success) {
        // If CFG recovered, classify functions
        auto classify = createFunctionClassificationMission(profile);
        classify.prerequisites.push_back(completed.id);
        followUps.push_back(classify);
    }
    
    metrics_.followUpMissionsGenerated += followUps.size();
    
    return followUps;
}

// ============================================================================
// Mission Template Creators
// ============================================================================

GeneratedMission MissionGenerator::createPackerDetectionMission(const BinaryProfile& profile) {
    GeneratedMission m;
    m.id = generateMissionId("packer_detection");
    m.description = "Detect packer/obfuscator in binary";
    m.missionType = "packer_detection";
    m.requiredCapabilities = {"CALCULATE_ENTROPY", "YARA_SCAN", "SCAN_PATTERNS"};
    m.targetSignature = profile.generateSignature();
    m.estimatedConfidence = estimateConfidence("packer_detection", profile);
    m.estimatedDuration = estimateDuration("packer_detection", profile);
    m.created = std::chrono::steady_clock::now();
    return m;
}

GeneratedMission MissionGenerator::createUnpackingMission(const BinaryProfile& profile) {
    GeneratedMission m;
    m.id = generateMissionId("unpacking");
    m.description = "Unpack compressed/encrypted binary";
    m.missionType = "unpacking";
    m.requiredCapabilities = {"UNPACK", "DUMP_MEMORY", "CALCULATE_ENTROPY"};
    m.targetSignature = profile.generateSignature();
    m.estimatedConfidence = estimateConfidence("unpacking", profile);
    m.estimatedDuration = estimateDuration("unpacking", profile);
    m.created = std::chrono::steady_clock::now();
    return m;
}

GeneratedMission MissionGenerator::createImportMappingMission(const BinaryProfile& profile) {
    GeneratedMission m;
    m.id = generateMissionId("import_mapping");
    m.description = "Map imported functions and dependencies";
    m.missionType = "import_mapping";
    m.requiredCapabilities = {"ANALYZE_IMPORTS", "QUERY_KNOWLEDGE"};
    m.targetSignature = profile.generateSignature();
    m.estimatedConfidence = estimateConfidence("import_mapping", profile);
    m.estimatedDuration = estimateDuration("import_mapping", profile);
    m.created = std::chrono::steady_clock::now();
    return m;
}

GeneratedMission MissionGenerator::createCFGRecoveryMission(const BinaryProfile& profile) {
    GeneratedMission m;
    m.id = generateMissionId("cfg_recovery");
    m.description = "Recover control flow graph";
    m.missionType = "cfg_recovery";
    m.requiredCapabilities = {"BUILD_CFG", "DISASSEMBLE", "DECOMPILE"};
    m.targetSignature = profile.generateSignature();
    m.estimatedConfidence = estimateConfidence("cfg_recovery", profile);
    m.estimatedDuration = estimateDuration("cfg_recovery", profile);
    m.created = std::chrono::steady_clock::now();
    return m;
}

GeneratedMission MissionGenerator::createFunctionClassificationMission(const BinaryProfile& profile) {
    GeneratedMission m;
    m.id = generateMissionId("function_classification");
    m.description = "Classify functions by behavior";
    m.missionType = "function_classification";
    m.requiredCapabilities = {"CLASSIFY_FUNCTION", "TRAIN_MODEL", "QUERY_KNOWLEDGE"};
    m.targetSignature = profile.generateSignature();
    m.estimatedConfidence = estimateConfidence("function_classification", profile);
    m.estimatedDuration = estimateDuration("function_classification", profile);
    m.created = std::chrono::steady_clock::now();
    return m;
}

GeneratedMission MissionGenerator::createStringExtractionMission(const BinaryProfile& profile) {
    GeneratedMission m;
    m.id = generateMissionId("string_extraction");
    m.description = "Extract and analyze strings";
    m.missionType = "string_extraction";
    m.requiredCapabilities = {"SCAN_PATTERNS", "QUERY_KNOWLEDGE"};
    m.targetSignature = profile.generateSignature();
    m.estimatedConfidence = estimateConfidence("string_extraction", profile);
    m.estimatedDuration = estimateDuration("string_extraction", profile);
    m.created = std::chrono::steady_clock::now();
    return m;
}

GeneratedMission MissionGenerator::createEntropyAnalysisMission(const BinaryProfile& profile) {
    GeneratedMission m;
    m.id = generateMissionId("entropy_analysis");
    m.description = "Analyze entropy across binary sections";
    m.missionType = "entropy_analysis";
    m.requiredCapabilities = {"CALCULATE_ENTROPY"};
    m.targetSignature = profile.generateSignature();
    m.estimatedConfidence = estimateConfidence("entropy_analysis", profile);
    m.estimatedDuration = estimateDuration("entropy_analysis", profile);
    m.created = std::chrono::steady_clock::now();
    return m;
}

GeneratedMission MissionGenerator::createAntiDebugDetectionMission(const BinaryProfile& profile) {
    GeneratedMission m;
    m.id = generateMissionId("anti_debug_detection");
    m.description = "Detect anti-debugging techniques";
    m.missionType = "anti_debug_detection";
    m.requiredCapabilities = {"SCAN_PATTERNS", "YARA_SCAN", "EXECUTE_SAMPLE"};
    m.targetSignature = profile.generateSignature();
    m.estimatedConfidence = estimateConfidence("anti_debug_detection", profile);
    m.estimatedDuration = estimateDuration("anti_debug_detection", profile);
    m.created = std::chrono::steady_clock::now();
    return m;
}

GeneratedMission MissionGenerator::createSymbolRecoveryMission(const BinaryProfile& profile) {
    GeneratedMission m;
    m.id = generateMissionId("symbol_recovery");
    m.description = "Recover debug symbols and names";
    m.missionType = "symbol_recovery";
    m.requiredCapabilities = {"QUERY_KNOWLEDGE", "ANALYZE_IMPORTS"};
    m.targetSignature = profile.generateSignature();
    m.estimatedConfidence = estimateConfidence("symbol_recovery", profile);
    m.estimatedDuration = estimateDuration("symbol_recovery", profile);
    m.created = std::chrono::steady_clock::now();
    return m;
}

GeneratedMission MissionGenerator::createYARAScanMission(const BinaryProfile& profile) {
    GeneratedMission m;
    m.id = generateMissionId("yara_scan");
    m.description = "Scan with YARA rules";
    m.missionType = "yara_scan";
    m.requiredCapabilities = {"YARA_SCAN", "QUERY_KNOWLEDGE"};
    m.targetSignature = profile.generateSignature();
    m.estimatedConfidence = estimateConfidence("yara_scan", profile);
    m.estimatedDuration = estimateDuration("yara_scan", profile);
    m.created = std::chrono::steady_clock::now();
    return m;
}

GeneratedMission MissionGenerator::createReportGenerationMission(const BinaryProfile& profile) {
    GeneratedMission m;
    m.id = generateMissionId("report");
    m.description = "Generate analysis report";
    m.missionType = "report";
    m.requiredCapabilities = {"EXPORT_JSON", "MERGE_RESULTS", "OPTIMIZE"};
    m.targetSignature = profile.generateSignature();
    m.estimatedConfidence = 0.95; // Reports are usually reliable
    m.estimatedDuration = estimateDuration("report", profile);
    m.created = std::chrono::steady_clock::now();
    return m;
}

// ============================================================================
// Utility Methods
// ============================================================================

std::string MissionGenerator::generateMissionId(const std::string& type) {
    return type + "_" + std::to_string(missionCounter_++);
}

double MissionGenerator::estimateConfidence(const std::string& missionType, 
                                               const BinaryProfile& profile) {
    if (missionType == "entropy_analysis") return 0.95;
    if (missionType == "packer_detection") return 0.85;
    if (missionType == "unpacking") return 0.70;
    if (missionType == "import_mapping") return 0.90;
    if (missionType == "cfg_recovery") return 0.75;
    if (missionType == "function_classification") return 0.65;
    if (missionType == "string_extraction") return 0.95;
    if (missionType == "anti_debug_detection") return 0.80;
    if (missionType == "symbol_recovery") return 0.85;
    if (missionType == "yara_scan") return 0.90;
    if (missionType == "report") return 0.95;
    return 0.75;
}

std::chrono::milliseconds MissionGenerator::estimateDuration(const std::string& missionType,
                                                                const BinaryProfile& profile) {
    auto baseSize = static_cast<long long>(profile.executableSizeMB * 10);
    
    if (missionType == "entropy_analysis") return std::chrono::milliseconds(100 + baseSize);
    if (missionType == "packer_detection") return std::chrono::milliseconds(200 + baseSize * 2);
    if (missionType == "unpacking") return std::chrono::milliseconds(500 + baseSize * 5);
    if (missionType == "import_mapping") return std::chrono::milliseconds(150 + baseSize);
    if (missionType == "cfg_recovery") return std::chrono::milliseconds(1000 + baseSize * 10);
    if (missionType == "function_classification") return std::chrono::milliseconds(500 + baseSize * 3);
    if (missionType == "string_extraction") return std::chrono::milliseconds(200 + baseSize);
    if (missionType == "anti_debug_detection") return std::chrono::milliseconds(300 + baseSize * 2);
    if (missionType == "symbol_recovery") return std::chrono::milliseconds(100 + baseSize);
    if (missionType == "yara_scan") return std::chrono::milliseconds(400 + baseSize * 3);
    if (missionType == "report") return std::chrono::milliseconds(100 + baseSize);
    return std::chrono::milliseconds(500);
}

} // namespace RawrXD::Agentic
