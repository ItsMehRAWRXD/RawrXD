/**
 * EmergentSelfCorrection.cpp
 *
 * Phase C.2 Batch 4/5: Emergent Self-Correction Implementation
 */

#include "EmergentSelfCorrection.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <random>
#include <fstream>

namespace Emergent {

// CorrectionAction implementation
std::string CorrectionAction::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"actionId\":\"" << actionId << "\",";
    json << "\"type\":" << static_cast<int>(type) << ",";
    json << "\"name\":\"" << name << "\",";
    json << "\"description\":\"" << description << "\",";
    json << "\"targetComponent\":\"" << targetComponent << "\",";
    json << "\"parameterAdjustments\":{";
    bool first = true;
    for (const auto& [key, val] : parameterAdjustments) {
        if (!first) json << ",";
        json << "\"" << key << "\":" << val;
        first = false;
    }
    json << "},";
    json << "\"expectedImprovement\":" << std::fixed << std::setprecision(4) << expectedImprovement << ",";
    json << "\"actualImprovement\":" << actualImprovement << ",";
    json << "\"wasEffective\":" << (wasEffective ? "true" : "false") << ",";
    json << "\"appliedAtMs\":" << appliedAtMs << ",";
    json << "\"evaluatedAtMs\":" << evaluatedAtMs << "}";
    return json.str();
}

// SelfCorrectionResult implementation
std::string SelfCorrectionResult::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"detectedInstabilities\":[";
    // Simplified - would include full instability objects
    json << "],";
    json << "\"appliedCorrections\":[";
    for (size_t i = 0; i < appliedCorrections.size(); ++i) {
        if (i > 0) json << ",";
        json << appliedCorrections[i].ToJson();
    }
    json << "],";
    json << "\"correctionDurationMs\":" << correctionDurationMs << ",";
    json << "\"overallImprovement\":" << overallImprovement << "}";
    return json.str();
}

void SelfCorrectionResult::PrintSummary() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           EMERGENT SELF-CORRECTION RESULTS                       ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Instabilities Detected: " << std::setw(10) << detectedInstabilities.size() << std::string(26, ' ') << "║\n";
    std::cout << "║  Corrections Applied:   " << std::setw(10) << appliedCorrections.size() << std::string(26, ' ') << "║\n";
    std::cout << "║  Correction Time:       " << std::setw(10) << correctionDurationMs << " ms" << std::string(23, ' ') << "║\n";
    std::cout << "║  Overall Improvement:   " << std::setw(10) << std::fixed << std::setprecision(2) << (overallImprovement * 100) << "%" << std::string(25, ' ') << "║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    
    if (!detectedInstabilities.empty()) {
        std::cout << "║  Detected Instabilities:                                       ║\n";
        for (const auto& inst : detectedInstabilities) {
            std::cout << "║    " << std::left << std::setw(20) << inst.source 
                      << " (severity: " << std::setw(5) << std::fixed << std::setprecision(2) << inst.severity << ")"
                      << std::string(15, ' ') << "║\n";
        }
    }
    
    if (!appliedCorrections.empty()) {
        std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
        std::cout << "║  Applied Corrections:                                          ║\n";
        for (const auto& action : appliedCorrections) {
            std::cout << "║    " << std::left << std::setw(20) << action.name 
                      << " -> " << std::setw(15) << action.targetComponent
                      << " (eff: " << std::setw(5) << std::fixed << std::setprecision(2) << action.wasEffective << ")"
                      << std::string(5, ' ') << "║\n";
        }
    }
    
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// EmergentSelfCorrection implementation
EmergentSelfCorrection::EmergentSelfCorrection() : lastCorrectionTime_(0) {}
EmergentSelfCorrection::~EmergentSelfCorrection() = default;

bool EmergentSelfCorrection::Initialize(const SelfCorrectionConfig& config) {
    config_ = config;
    healthHistory_.clear();
    activeInstabilities_.clear();
    correctionHistory_.clear();
    lastCorrectionTime_ = 0;
    strategySuccessRates_.clear();
    effectiveAdjustments_.clear();
    std::cout << "[EmergentSelfCorrection] Initialized\n";
    return true;
}

void EmergentSelfCorrection::UpdateHealth(const HealthSnapshot& snapshot) {
    healthHistory_.push_back(snapshot);
    
    // Keep only recent history
    if (healthHistory_.size() > 100) {
        healthHistory_.erase(healthHistory_.begin());
    }
}

SelfCorrectionResult EmergentSelfCorrection::Correct() {
    auto startTime = std::chrono::high_resolution_clock::now();
    
    SelfCorrectionResult result;
    
    if (healthHistory_.empty()) {
        result.overallImprovement = 0.0;
        return result;
    }
    
    const HealthSnapshot& currentHealth = healthHistory_.back();
    result.healthBefore = currentHealth;
    
    // Detect instabilities
    result.detectedInstabilities = DetectInstabilities(currentHealth);
    activeInstabilities_ = result.detectedInstabilities;
    
    // Plan corrections
    auto strategies = PlanCorrections(result.detectedInstabilities);
    
    // Apply corrections
    for (const auto& strategy : strategies) {
        if (!CanApplyCorrection()) break;
        
        auto action = ApplyCorrection(strategy);
        result.appliedCorrections.push_back(action);
        correctionHistory_.push_back(action);
        
        lastCorrectionTime_ = action.appliedAtMs;
    }
    
    // Evaluate corrections (simplified - would wait for evaluation window)
    for (auto& action : result.appliedCorrections) {
        action.wasEffective = action.actualImprovement >= config_.effectivenessThreshold;
        if (config_.enableLearning) {
            LearnFromCorrection(action);
        }
    }
    
    // Calculate overall improvement
    if (!result.appliedCorrections.empty()) {
        double totalImprovement = 0.0;
        for (const auto& action : result.appliedCorrections) {
            totalImprovement += action.actualImprovement;
        }
        result.overallImprovement = totalImprovement / result.appliedCorrections.size();
    }
    
    // Simulate health after correction
    result.healthAfter = currentHealth;
    result.healthAfter.overallHealth = std::min(1.0, currentHealth.overallHealth + result.overallImprovement);
    result.healthAfter.activeInstabilities.clear();
    result.healthAfter.activeCorrectionCount = 0;
    
    auto endTime = std::chrono::high_resolution_clock::now();
    result.correctionDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    
    std::cout << "[EmergentSelfCorrection] Correction cycle complete: " 
              << result.appliedCorrections.size() << " corrections applied\n";
    
    return result;
}

std::vector<Instability> EmergentSelfCorrection::DetectInstabilities(const HealthSnapshot& snapshot) {
    std::vector<Instability> instabilities;
    
    // Check overall health
    if (snapshot.overallHealth < config_.instabilityThreshold) {
        Instability inst;
        inst.instabilityId = GenerateInstabilityId();
        inst.description = "Overall system health below threshold";
        inst.severity = 1.0 - snapshot.overallHealth;
        inst.source = "system";
        inst.metrics["health"] = snapshot.overallHealth;
        inst.detectedAtMs = snapshot.timestampMs;
        inst.isResolved = false;
        instabilities.push_back(inst);
    }
    
    // Check component healths
    for (const auto& [component, health] : snapshot.componentHealths) {
        if (health < config_.instabilityThreshold) {
            Instability inst;
            inst.instabilityId = GenerateInstabilityId();
            inst.description = component + " health degraded";
            inst.severity = 1.0 - health;
            inst.source = component;
            inst.metrics["health"] = health;
            inst.detectedAtMs = snapshot.timestampMs;
            inst.isResolved = false;
            instabilities.push_back(inst);
        }
    }
    
    // Check stability metrics
    if (snapshot.convergenceStability < config_.instabilityThreshold) {
        Instability inst;
        inst.instabilityId = GenerateInstabilityId();
        inst.description = "Convergence stability degraded";
        inst.severity = 1.0 - snapshot.convergenceStability;
        inst.source = "convergence";
        inst.metrics["stability"] = snapshot.convergenceStability;
        inst.detectedAtMs = snapshot.timestampMs;
        inst.isResolved = false;
        instabilities.push_back(inst);
    }
    
    return instabilities;
}

std::vector<CorrectionStrategy> EmergentSelfCorrection::PlanCorrections(const std::vector<Instability>& instabilities) {
    std::vector<CorrectionStrategy> strategies;
    
    for (const auto& inst : instabilities) {
        CorrectionStrategy strategy;
        strategy.targetComponent = inst.source;
        
        // Select correction type based on source
        if (inst.source == "convergence") {
            strategy.type = CorrectionType::HARMONIC_REBALANCE;
            strategy.parameterAdjustments["harmony_weight"] = 0.1;
            strategy.expectedImprovement = 0.2;
        } else if (inst.source == "scheduler") {
            strategy.type = CorrectionType::SCHEDULING_MODIFICATION;
            strategy.parameterAdjustments["exploration_rate"] = -0.1;
            strategy.expectedImprovement = 0.15;
        } else if (inst.source == "system") {
            strategy.type = CorrectionType::TOPOLOGY_ADJUSTMENT;
            strategy.parameterAdjustments["graph_density"] = 0.05;
            strategy.expectedImprovement = 0.1;
        } else {
            strategy.type = CorrectionType::RESOURCE_REALLOCATION;
            strategy.parameterAdjustments["resource_allocation"] = 0.1;
            strategy.expectedImprovement = 0.1;
        }
        
        strategy.priority = static_cast<int>(inst.severity * 10);
        strategies.push_back(strategy);
    }
    
    // Sort by priority
    std::sort(strategies.begin(), strategies.end(),
        [](const CorrectionStrategy& a, const CorrectionStrategy& b) { return a.priority > b.priority; });
    
    // Limit number of corrections
    if (strategies.size() > static_cast<size_t>(config_.maxConcurrentCorrections)) {
        strategies.resize(config_.maxConcurrentCorrections);
    }
    
    return strategies;
}

CorrectionAction EmergentSelfCorrection::ApplyCorrection(const CorrectionStrategy& strategy) {
    CorrectionAction action;
    action.actionId = GenerateActionId();
    action.type = strategy.type;
    action.targetComponent = strategy.targetComponent;
    action.parameterAdjustments = strategy.parameterAdjustments;
    action.expectedImprovement = strategy.expectedImprovement;
    action.actualImprovement = 0.0;  // Will be updated after evaluation
    action.wasEffective = false;
    action.appliedAtMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    action.evaluatedAtMs = 0;
    
    // Set name based on type
    switch (strategy.type) {
        case CorrectionType::TOPOLOGY_ADJUSTMENT: action.name = "Topology Adjustment"; break;
        case CorrectionType::SCHEDULING_MODIFICATION: action.name = "Scheduling Modification"; break;
        case CorrectionType::HARMONIC_REBALANCE: action.name = "Harmonic Rebalance"; break;
        case CorrectionType::RESOURCE_REALLOCATION: action.name = "Resource Reallocation"; break;
        case CorrectionType::PATTERN_SUPPRESSION: action.name = "Pattern Suppression"; break;
        case CorrectionType::PATTERN_AMPLIFICATION: action.name = "Pattern Amplification"; break;
        default: action.name = "Unknown Correction"; break;
    }
    
    action.description = "Applied " + action.name + " to " + strategy.targetComponent;
    
    std::cout << "[EmergentSelfCorrection] Applied " << action.name 
              << " to " << strategy.targetComponent << "\n";
    
    return action;
}

bool EmergentSelfCorrection::EvaluateCorrection(CorrectionAction& action, const HealthSnapshot& before, const HealthSnapshot& after) {
    // Calculate actual improvement
    action.actualImprovement = after.overallHealth - before.overallHealth;
    action.wasEffective = action.actualImprovement >= config_.effectivenessThreshold;
    action.evaluatedAtMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    return action.wasEffective;
}

void EmergentSelfCorrection::ForceCorrection(CorrectionType type, const std::string& target) {
    CorrectionStrategy strategy;
    strategy.type = type;
    strategy.targetComponent = target;
    strategy.expectedImprovement = 0.1;
    strategy.priority = 10;
    
    auto action = ApplyCorrection(strategy);
    correctionHistory_.push_back(action);
}

void EmergentSelfCorrection::RevertCorrection(const std::string& actionId) {
    // Find and mark as reverted
    for (auto& action : correctionHistory_) {
        if (action.actionId == actionId) {
            action.wasEffective = false;
            action.actualImprovement = -0.1;  // Negative improvement
            break;
        }
    }
}

bool EmergentSelfCorrection::SaveCorrectionHistory(const std::string& path) const {
    std::ofstream file(path);
    if (!file.is_open()) return false;
    
    file << "[";
    for (size_t i = 0; i < correctionHistory_.size(); ++i) {
        if (i > 0) file << ",";
        file << correctionHistory_[i].ToJson();
    }
    file << "]";
    return true;
}

bool EmergentSelfCorrection::LoadCorrectionHistory(const std::string& path) {
    // Simplified load
    return false;
}

// Helper methods
double EmergentSelfCorrection::CalculateInstabilitySeverity(const HealthSnapshot& snapshot, const std::string& component) {
    auto it = snapshot.componentHealths.find(component);
    if (it != snapshot.componentHealths.end()) {
        return 1.0 - it->second;
    }
    return 0.0;
}

CorrectionStrategy EmergentSelfCorrection::SelectBestStrategy(const std::vector<CorrectionStrategy>& strategies) {
    if (strategies.empty()) {
        return CorrectionStrategy{};
    }
    
    // Select based on expected improvement and learned success rate
    CorrectionStrategy best = strategies[0];
    double bestScore = best.expectedImprovement;
    
    auto it = strategySuccessRates_.find(best.type);
    if (it != strategySuccessRates_.end()) {
        bestScore *= it->second;
    }
    
    for (const auto& strategy : strategies) {
        double score = strategy.expectedImprovement;
        auto rateIt = strategySuccessRates_.find(strategy.type);
        if (rateIt != strategySuccessRates_.end()) {
            score *= rateIt->second;
        }
        
        if (score > bestScore) {
            best = strategy;
            bestScore = score;
        }
    }
    
    return best;
}

bool EmergentSelfCorrection::CanApplyCorrection() const {
    auto now = std::chrono::system_clock::now();
    auto currentTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    return (currentTime - lastCorrectionTime_) >= config_.minCorrectionIntervalMs;
}

void EmergentSelfCorrection::LearnFromCorrection(const CorrectionAction& action) {
    // Update success rate for this correction type
    auto& rate = strategySuccessRates_[action.type];
    rate = (rate * 0.9) + ((action.wasEffective ? 1.0 : 0.0) * 0.1);
    
    // Store effective adjustments
    if (action.wasEffective) {
        effectiveAdjustments_[action.targetComponent] = action.parameterAdjustments;
    }
}

std::string EmergentSelfCorrection::GenerateInstabilityId() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1000, 9999);
    
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    std::ostringstream id;
    id << "inst-" << ms << "-" << dis(gen);
    return id.str();
}

std::string EmergentSelfCorrection::GenerateActionId() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1000, 9999);
    
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    std::ostringstream id;
    id << "corr-" << ms << "-" << dis(gen);
    return id.str();
}

// CLI Implementation
void EmergentSelfCorrectionCLI::PrintBanner() {
    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                                                ║\n";
    std::cout << "║     EMERGENT SELF-CORRECTION - Phase C.2                       ║\n";
    std::cout << "║     Autonomous Stability Maintenance                           ║\n";
    std::cout << "║                                                                ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n\n";
}

void EmergentSelfCorrectionCLI::PrintUsage() {
    std::cout << "Usage: emergent-correction [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --threshold X       Instability threshold (0-1)\n";
    std::cout << "  --max-corrections N Maximum concurrent corrections\n";
    std::cout << "  --learning          Enable learning\n";
    std::cout << "  --output PATH       Save history to file\n";
    std::cout << "  --json              Output results as JSON\n";
    std::cout << "  --help              Show this help\n\n";
}

SelfCorrectionConfig EmergentSelfCorrectionCLI::ParseArgs(int argc, char* argv[]) {
    SelfCorrectionConfig config;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--threshold" && i + 1 < argc) {
            config.instabilityThreshold = std::stod(argv[++i]);
        } else if (arg == "--max-corrections" && i + 1 < argc) {
            config.maxConcurrentCorrections = std::stoi(argv[++i]);
        } else if (arg == "--learning") {
            config.enableLearning = true;
        } else if (arg == "--help" || arg == "-h") {
            PrintUsage();
            exit(0);
        }
    }
    
    return config;
}

int EmergentSelfCorrectionCLI::Run(int argc, char* argv[]) {
    PrintBanner();
    
    if (argc > 1 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        PrintUsage();
        return 0;
    }
    
    SelfCorrectionConfig config = ParseArgs(argc, argv);
    
    // Create self-correction system
    EmergentSelfCorrection correction;
    correction.Initialize(config);
    
    // Generate synthetic health snapshots
    std::cout << "[Demo] Generating synthetic health snapshots...\n";
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> healthDist(0.5, 0.95);
    
    for (int i = 0; i < 10; ++i) {
        HealthSnapshot snapshot;
        snapshot.timestampMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count() + (i * 1000);
        snapshot.overallHealth = healthDist(gen);
        snapshot.componentHealths["engine"] = healthDist(gen);
        snapshot.componentHealths["swarm"] = healthDist(gen);
        snapshot.componentHealths["telemetry"] = healthDist(gen);
        snapshot.convergenceStability = healthDist(gen);
        snapshot.performanceStability = healthDist(gen);
        snapshot.resourceStability = healthDist(gen);
        snapshot.activeCorrectionCount = 0;
        correction.UpdateHealth(snapshot);
    }
    
    // Run correction cycle
    std::cout << "[Demo] Running self-correction cycle...\n";
    auto result = correction.Correct();
    
    // Print summary
    result.PrintSummary();
    
    // Check for output path
    std::string outputPath;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--output" && i + 1 < argc) {
            outputPath = argv[i + 1];
        }
    }
    
    if (!outputPath.empty()) {
        if (correction.SaveCorrectionHistory(outputPath)) {
            std::cout << "Correction history saved to: " << outputPath << "\n";
        }
    }
    
    // Output JSON if requested
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--json") {
            std::cout << "\n" << result.ToJson() << "\n";
        }
    }
    
    return 0;
}

} // namespace Emergent
