/**
 * InfinitePerfectionTelemetry.cpp
 * 
 * Phase B.2: Swarm Integration - Telemetry Bridge Implementation
 */

#include "InfinitePerfectionTelemetry.hpp"
#include <sstream>
#include <iomanip>
#include <numeric>

namespace Sovereign {

InfinitePerfectionTelemetry::InfinitePerfectionTelemetry(
    InfinitePerfection::InfinitePerfectionEngine* engine)
    : engine_(engine), totalCyclesExecuted_(0) {}

UnityCycleTelemetry InfinitePerfectionTelemetry::CaptureUnityCycle() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    UnityCycleTelemetry telemetry;
    
    if (!engine_) {
        return telemetry;
    }
    
    // Capture all Unity Cycle fields (243-249)
    auto unity = engine_->ComputeUnity();
    auto integration = engine_->ComputeIntegration();
    auto synthesis = engine_->ComputeSynthesis();
    auto convergence = engine_->ComputeConvergence();
    auto coherence = engine_->ComputeCoherence();
    auto harmony = engine_->ComputeHarmony();
    auto balance = engine_->ComputeBalance();
    
    // Batch 243: Unity
    telemetry.unityPotential = unity.unityPotential;
    telemetry.cycleIntegration = unity.cycleIntegration;
    telemetry.harmonicConvergence = unity.harmonicConvergence;
    
    // Batch 244: Integration
    telemetry.integrationCoherence = integration.cycleIntegration;
    telemetry.crossCycleAlignment = integration.crossCycleAlignment;
    telemetry.phaseLockStrength = integration.phaseLockStrength;
    
    // Batch 245: Synthesis
    telemetry.emergenceDensity = synthesis.emergenceDensity;
    telemetry.patternNovelty = synthesis.patternNovelty;
    telemetry.crossCycleSynergy = synthesis.crossCycleSynergy;
    
    // Batch 246: Convergence
    telemetry.focalPointDensity = convergence.focalPointDensity;
    telemetry.attractorStrength = convergence.attractorStrength;
    telemetry.convergenceCoherence = convergence.convergenceCoherence;
    
    // Batch 247: Coherence
    telemetry.coherenceStability = coherence.coherenceStability;
    telemetry.unifiedPatternIndex = coherence.unifiedPatternIndex;
    telemetry.harmonicConsistency = coherence.harmonicConsistency;
    
    // Batch 248: Harmony
    telemetry.resonanceAmplitude = harmony.resonanceAmplitude;
    telemetry.harmonicStability = harmony.harmonicStability;
    telemetry.sovereignHarmonyIndex = harmony.sovereignHarmonyIndex;
    
    // Batch 249: Balance
    telemetry.equilibriumStrength = balance.equilibriumStrength;
    telemetry.stabilityIndex = balance.stabilityIndex;
    telemetry.symmetryCoefficient = balance.symmetryCoefficient;
    
    // Metadata
    telemetry.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    telemetry.cycleCount = static_cast<uint32_t>(totalCyclesExecuted_);
    telemetry.isConverged = IsConverged();
    
    return telemetry;
}

void InfinitePerfectionTelemetry::RecordSwarmExecution(
    uint32_t agentId,
    const std::string& taskKind,
    const std::string& engineCycle,
    float confidence,
    int64_t executionTimeMs,
    bool success) {
    
    std::lock_guard<std::mutex> lock(mutex_);
    
    SwarmExecutionTelemetry execution;
    execution.agentId = agentId;
    execution.taskKind = taskKind;
    execution.engineCycle = engineCycle;
    execution.confidence = confidence;
    execution.executionTimeMs = executionTimeMs;
    execution.success = success;
    execution.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    executionHistory_.push_back(execution);
    totalCyclesExecuted_++;
    
    // Keep only last 10000 executions
    if (executionHistory_.size() > 10000) {
        executionHistory_.erase(executionHistory_.begin());
    }
}

InfinitePerfectionTelemetrySnapshot InfinitePerfectionTelemetry::GetSnapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    InfinitePerfectionTelemetrySnapshot snapshot;
    snapshot.unityCycle = CaptureUnityCycle();
    snapshot.swarmExecutions = executionHistory_;
    snapshot.snapshotTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    snapshot.totalCyclesExecuted = totalCyclesExecuted_;
    snapshot.averageConvergenceRate = GetConvergenceScore();
    
    return snapshot;
}

std::string InfinitePerfectionTelemetry::ExportToJson() const {
    auto snapshot = GetSnapshot();
    auto& t = snapshot.unityCycle;
    
    std::ostringstream json;
    json << "{" << std::endl;
    json << "  \"timestamp\": " << snapshot.snapshotTime << "," << std::endl;
    json << "  \"totalCyclesExecuted\": " << snapshot.totalCyclesExecuted << "," << std::endl;
    json << "  \"averageConvergenceRate\": " << std::fixed << std::setprecision(4) 
         << snapshot.averageConvergenceRate << "," << std::endl;
    json << "  \"unityCycle\": {" << std::endl;
    json << "    \"unityPotential\": " << t.unityPotential << "," << std::endl;
    json << "    \"cycleIntegration\": " << t.cycleIntegration << "," << std::endl;
    json << "    \"harmonicConvergence\": " << t.harmonicConvergence << "," << std::endl;
    json << "    \"integrationCoherence\": " << t.integrationCoherence << "," << std::endl;
    json << "    \"crossCycleAlignment\": " << t.crossCycleAlignment << "," << std::endl;
    json << "    \"phaseLockStrength\": " << t.phaseLockStrength << "," << std::endl;
    json << "    \"emergenceDensity\": " << t.emergenceDensity << "," << std::endl;
    json << "    \"patternNovelty\": " << t.patternNovelty << "," << std::endl;
    json << "    \"crossCycleSynergy\": " << t.crossCycleSynergy << "," << std::endl;
    json << "    \"focalPointDensity\": " << t.focalPointDensity << "," << std::endl;
    json << "    \"attractorStrength\": " << t.attractorStrength << "," << std::endl;
    json << "    \"convergenceCoherence\": " << t.convergenceCoherence << "," << std::endl;
    json << "    \"coherenceStability\": " << t.coherenceStability << "," << std::endl;
    json << "    \"unifiedPatternIndex\": " << t.unifiedPatternIndex << "," << std::endl;
    json << "    \"harmonicConsistency\": " << t.harmonicConsistency << "," << std::endl;
    json << "    \"resonanceAmplitude\": " << t.resonanceAmplitude << "," << std::endl;
    json << "    \"harmonicStability\": " << t.harmonicStability << "," << std::endl;
    json << "    \"sovereignHarmonyIndex\": " << t.sovereignHarmonyIndex << "," << std::endl;
    json << "    \"equilibriumStrength\": " << t.equilibriumStrength << "," << std::endl;
    json << "    \"stabilityIndex\": " << t.stabilityIndex << "," << std::endl;
    json << "    \"symmetryCoefficient\": " << t.symmetryCoefficient << "," << std::endl;
    json << "    \"isConverged\": " << (t.isConverged ? "true" : "false") << std::endl;
    json << "  }" << std::endl;
    json << "}" << std::endl;
    
    return json.str();
}

bool InfinitePerfectionTelemetry::ExportToSQLite(const std::string& dbPath) const {
    // Placeholder for SQLite export
    // Would use SQLite C API to insert records
    return true;
}

bool InfinitePerfectionTelemetry::IsConverged() const {
    if (!engine_) return false;
    
    auto t = CaptureUnityCycle();
    
    // Converged if all key metrics > 0.8
    return (t.unityPotential > 0.8 &&
            t.cycleIntegration > 0.8 &&
            t.harmonicConvergence > 0.8 &&
            t.integrationCoherence > 0.8 &&
            t.coherenceStability > 0.8 &&
            t.sovereignHarmonyIndex > 0.8 &&
            t.equilibriumStrength > 0.8);
}

double InfinitePerfectionTelemetry::GetConvergenceScore() const {
    if (!engine_) return 0.0;
    
    auto t = CaptureUnityCycle();
    
    // Average of all key convergence metrics
    double sum = (t.unityPotential +
                  t.cycleIntegration +
                  t.harmonicConvergence +
                  t.integrationCoherence +
                  t.coherenceStability +
                  t.sovereignHarmonyIndex +
                  t.equilibriumStrength) / 7.0;
    
    return sum;
}

void InfinitePerfectionTelemetry::Reset() {
    std::lock_guard<std::mutex> lock(mutex_);
    executionHistory_.clear();
    totalCyclesExecuted_ = 0;
}

} // namespace Sovereign
