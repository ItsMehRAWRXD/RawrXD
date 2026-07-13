#pragma once

/**
 * InfinitePerfectionTelemetry.hpp
 * 
 * Phase B.2: Swarm Integration - Telemetry Bridge
 * 
 * Exports InfinitePerfectionEngine harmonic fields to the telemetry system.
 * Enables real-time monitoring of Unity Cycle (243-249) convergence.
 */

#include "../infinite/InfinitePerfectionEngine.hpp"
#include <string>
#include <vector>
#include <chrono>
#include <map>

namespace Sovereign {

// Forward declaration
namespace InfinitePerfection { class InfinitePerfectionEngine; }

/**
 * Telemetry snapshot for a single Unity Cycle field
 */
struct UnityCycleTelemetry {
    // Batch 243: Unity
    double unityPotential = 0.0;
    double cycleIntegration = 0.0;
    double harmonicConvergence = 0.0;
    
    // Batch 244: Integration
    double integrationCoherence = 0.0;
    double crossCycleAlignment = 0.0;
    double phaseLockStrength = 0.0;
    
    // Batch 245: Synthesis
    double emergenceDensity = 0.0;
    double patternNovelty = 0.0;
    double crossCycleSynergy = 0.0;
    
    // Batch 246: Convergence
    double focalPointDensity = 0.0;
    double attractorStrength = 0.0;
    double convergenceCoherence = 0.0;
    
    // Batch 247: Coherence
    double coherenceStability = 0.0;
    double unifiedPatternIndex = 0.0;
    double harmonicConsistency = 0.0;
    
    // Batch 248: Harmony
    double resonanceAmplitude = 0.0;
    double harmonicStability = 0.0;
    double sovereignHarmonyIndex = 0.0;
    
    // Batch 249: Balance
    double equilibriumStrength = 0.0;
    double stabilityIndex = 0.0;
    double symmetryCoefficient = 0.0;
    
    // Metadata
    int64_t timestamp = 0;
    uint32_t cycleCount = 0;
    bool isConverged = false;
};

/**
 * Swarm execution telemetry
 */
struct SwarmExecutionTelemetry {
    uint32_t agentId = 0;
    std::string taskKind;
    std::string engineCycle;
    float confidence = 0.0f;
    int64_t executionTimeMs = 0;
    bool success = false;
    int64_t timestamp = 0;
};

/**
 * Complete telemetry snapshot
 */
struct InfinitePerfectionTelemetrySnapshot {
    UnityCycleTelemetry unityCycle;
    std::vector<SwarmExecutionTelemetry> swarmExecutions;
    int64_t snapshotTime = 0;
    uint64_t totalCyclesExecuted = 0;
    double averageConvergenceRate = 0.0;
};

/**
 * Telemetry bridge between InfinitePerfectionEngine and Swarm
 */
class InfinitePerfectionTelemetry {
public:
    explicit InfinitePerfectionTelemetry(InfinitePerfection::InfinitePerfectionEngine* engine);
    
    // Capture current engine state
    UnityCycleTelemetry CaptureUnityCycle() const;
    
    // Record swarm execution
    void RecordSwarmExecution(uint32_t agentId, const std::string& taskKind, 
                              const std::string& engineCycle, float confidence,
                              int64_t executionTimeMs, bool success);
    
    // Get full snapshot
    InfinitePerfectionTelemetrySnapshot GetSnapshot() const;
    
    // Export to JSON for dashboard
    std::string ExportToJson() const;
    
    // Export to SQLite for persistence
    bool ExportToSQLite(const std::string& dbPath) const;
    
    // Check if system is converged (all cycles > 0.8)
    bool IsConverged() const;
    
    // Get convergence score (0.0 - 1.0)
    double GetConvergenceScore() const;
    
    // Reset telemetry
    void Reset();
    
private:
    InfinitePerfection::InfinitePerfectionEngine* engine_;
    mutable std::mutex mutex_;
    std::vector<SwarmExecutionTelemetry> executionHistory_;
    uint64_t totalCyclesExecuted_ = 0;
};

} // namespace Sovereign
