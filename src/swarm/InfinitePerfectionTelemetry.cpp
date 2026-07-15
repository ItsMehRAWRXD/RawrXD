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
    telemetry.sovereignEmergenceIndex = synthesis.sovereignEmergenceIndex;
    
    // Batch 246: Convergence
    telemetry.focalPointDensity = convergence.focalPointDensity;
    telemetry.attractorStrength = convergence.attractorStrength;
    telemetry.convergenceCoherence = convergence.convergenceCoherence;
    telemetry.sovereignConvergenceIndex = convergence.sovereignConvergenceIndex;
    
    // Batch 247: Coherence
    telemetry.coherenceStability = coherence.coherenceStability;
    telemetry.unifiedPatternIndex = coherence.unifiedPatternIndex;
    telemetry.harmonicConsistency = coherence.harmonicConsistency;
    telemetry.sovereignCoherenceIndex = coherence.sovereignCoherenceIndex;
    
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
    // Phase B.2 Batch 3/5: Persistent Telemetry
    // SQLite implementation for durable storage
    
    sqlite3* db = nullptr;
    int rc = sqlite3_open(dbPath.c_str(), &db);
    if (rc != SQLITE_OK) {
        std::cerr << "[Telemetry] Failed to open SQLite DB: " << sqlite3_errmsg(db) << std::endl;
        if (db) sqlite3_close(db);
        return false;
    }
    
    // Create tables if they don't exist
    const char* createCycleMetricsSQL = R"(
        CREATE TABLE IF NOT EXISTS cycle_metrics (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            cycle_name TEXT NOT NULL,
            batch INTEGER NOT NULL,
            score REAL NOT NULL,
            execution_ms INTEGER,
            timestamp INTEGER NOT NULL,
            convergence_status TEXT
        );
    )";
    
    const char* createSwarmExecutionsSQL = R"(
        CREATE TABLE IF NOT EXISTS swarm_executions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id INTEGER NOT NULL,
            task_kind TEXT NOT NULL,
            engine_cycle TEXT NOT NULL,
            confidence REAL,
            execution_time_ms INTEGER,
            success BOOLEAN,
            timestamp INTEGER NOT NULL
        );
    )";
    
    const char* createConvergenceEventsSQL = R"(
        CREATE TABLE IF NOT EXISTS convergence_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            global_harmony_index REAL NOT NULL,
            is_converged BOOLEAN NOT NULL,
            timestamp INTEGER NOT NULL
        );
    )";
    
    char* errMsg = nullptr;
    rc = sqlite3_exec(db, createCycleMetricsSQL, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "[Telemetry] Failed to create cycle_metrics table: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        sqlite3_close(db);
        return false;
    }
    
    rc = sqlite3_exec(db, createSwarmExecutionsSQL, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "[Telemetry] Failed to create swarm_executions table: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        sqlite3_close(db);
        return false;
    }
    
    rc = sqlite3_exec(db, createConvergenceEventsSQL, nullptr, nullptr, &errMsg);
    if (rc != SQLITE_OK) {
        std::cerr << "[Telemetry] Failed to create convergence_events table: " << errMsg << std::endl;
        sqlite3_free(errMsg);
        sqlite3_close(db);
        return false;
    }
    
    // Insert cycle metrics
    auto t = CaptureUnityCycle();
    int64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    struct CycleMetric {
        const char* name;
        int batch;
        double score;
    };
    
    CycleMetric metrics[] = {
        {"Unity", 243, t.unityPotential},
        {"Integration", 244, t.cycleIntegration},
        {"Synthesis", 245, t.sovereignEmergenceIndex},
        {"Convergence", 246, t.sovereignConvergenceIndex},
        {"Coherence", 247, t.sovereignCoherenceIndex},
        {"Harmony", 248, t.sovereignHarmonyIndex},
        {"Balance", 249, t.equilibriumStrength}
    };
    
    sqlite3_stmt* stmt = nullptr;
    const char* insertMetricSQL = "INSERT INTO cycle_metrics (cycle_name, batch, score, timestamp, convergence_status) VALUES (?, ?, ?, ?, ?);";
    
    for (const auto& metric : metrics) {
        rc = sqlite3_prepare_v2(db, insertMetricSQL, -1, &stmt, nullptr);
        if (rc == SQLITE_OK) {
            sqlite3_bind_text(stmt, 1, metric.name, -1, SQLITE_STATIC);
            sqlite3_bind_int(stmt, 2, metric.batch);
            sqlite3_bind_double(stmt, 3, metric.score);
            sqlite3_bind_int64(stmt, 4, now);
            sqlite3_bind_text(stmt, 5, IsConverged() ? "CONVERGED" : "CONVERGING", -1, SQLITE_STATIC);
            
            rc = sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
    
    // Insert swarm executions
    const char* insertExecutionSQL = "INSERT INTO swarm_executions (agent_id, task_kind, engine_cycle, confidence, execution_time_ms, success, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?);";
    
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& exec : executionHistory_) {
        rc = sqlite3_prepare_v2(db, insertExecutionSQL, -1, &stmt, nullptr);
        if (rc == SQLITE_OK) {
            sqlite3_bind_int(stmt, 1, exec.agentId);
            sqlite3_bind_text(stmt, 2, exec.taskKind.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 3, exec.engineCycle.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_double(stmt, 4, exec.confidence);
            sqlite3_bind_int64(stmt, 5, exec.executionTimeMs);
            sqlite3_bind_int(stmt, 6, exec.success ? 1 : 0);
            sqlite3_bind_int64(stmt, 7, exec.timestamp);
            
            rc = sqlite3_step(stmt);
            sqlite3_finalize(stmt);
        }
    }
    
    // Insert convergence event
    const char* insertConvergenceSQL = "INSERT INTO convergence_events (global_harmony_index, is_converged, timestamp) VALUES (?, ?, ?);";
    rc = sqlite3_prepare_v2(db, insertConvergenceSQL, -1, &stmt, nullptr);
    if (rc == SQLITE_OK) {
        sqlite3_bind_double(stmt, 1, GetConvergenceScore());
        sqlite3_bind_int(stmt, 2, IsConverged() ? 1 : 0);
        sqlite3_bind_int64(stmt, 3, now);
        
        rc = sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    
    sqlite3_close(db);
    
    std::cout << "[Telemetry] Exported to SQLite: " << dbPath << std::endl;
    std::cout << "[Telemetry]   - Cycle metrics: 7 records" << std::endl;
    std::cout << "[Telemetry]   - Swarm executions: " << executionHistory_.size() << " records" << std::endl;
    std::cout << "[Telemetry]   - Convergence event: 1 record" << std::endl;
    
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
