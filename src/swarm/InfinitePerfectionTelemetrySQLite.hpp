#pragma once

/**
 * InfinitePerfectionTelemetrySQLite.hpp
 * 
 * Phase B.2 Batch 3/5: SQLite Persistence Layer
 * 
 * Provides durable storage for telemetry data with automatic table creation
 * and efficient batch inserts.
 */

#include <string>
#include <vector>
#include <memory>
#include <functional>

// Forward declaration for SQLite
struct sqlite3;

namespace Sovereign {

// Forward declarations
struct UnityCycleTelemetry;
struct SwarmExecutionTelemetry;
struct InfinitePerfectionTelemetrySnapshot;

/**
 * SQLite persistence manager for InfinitePerfectionEngine telemetry
 */
class InfinitePerfectionTelemetrySQLite {
public:
    explicit InfinitePerfectionTelemetrySQLite(const std::string& dbPath);
    ~InfinitePerfectionTelemetrySQLite();
    
    // Initialize database with required tables
    bool Initialize();
    
    // Check if database is open and ready
    bool IsOpen() const;
    
    // Store Unity Cycle telemetry
    bool StoreUnityCycle(const UnityCycleTelemetry& telemetry);
    
    // Store Swarm execution
    bool StoreSwarmExecution(const SwarmExecutionTelemetry& execution);
    
    // Store complete snapshot
    bool StoreSnapshot(const InfinitePerfectionTelemetrySnapshot& snapshot);
    
    // Query methods
    std::vector<UnityCycleTelemetry> QueryUnityCycles(
        int64_t startTime = 0,
        int64_t endTime = 0,
        int limit = 100
    ) const;
    
    std::vector<SwarmExecutionTelemetry> QuerySwarmExecutions(
        int64_t startTime = 0,
        int64_t endTime = 0,
        int limit = 100
    ) const;
    
    // Get convergence history
    std::vector<std::pair<int64_t, double>> QueryConvergenceHistory(
        int64_t startTime = 0,
        int64_t endTime = 0
    ) const;
    
    // Get statistics
    struct TelemetryStats {
        int64_t totalExecutions = 0;
        int64_t successfulExecutions = 0;
        int64_t failedExecutions = 0;
        double averageExecutionTimeMs = 0.0;
        double averageConvergenceScore = 0.0;
        int64_t firstTimestamp = 0;
        int64_t lastTimestamp = 0;
    };
    
    TelemetryStats GetStatistics(int64_t startTime = 0, int64_t endTime = 0) const;
    
    // Export to JSON
    std::string ExportToJson(int64_t startTime = 0, int64_t endTime = 0) const;
    
    // Vacuum and optimize
    bool Optimize();
    
    // Close database
    void Close();
    
private:
    std::string dbPath_;
    sqlite3* db_ = nullptr;
    bool initialized_ = false;
    
    // Execute SQL without results
    bool ExecuteSQL(const std::string& sql);
    
    // Execute SQL with callback
    bool ExecuteQuery(const std::string& sql, 
                      const std::function<void(int argc, char** argv, char** colNames)>& callback);
    
    // Create tables
    bool CreateTables();
    
    // Prepare statements for batch inserts
    bool PrepareStatements();
    void FinalizeStatements();
    
    // Statement handles
    struct Statements {
        void* insertUnityCycle = nullptr;
        void* insertSwarmExecution = nullptr;
        void* insertConvergenceEvent = nullptr;
    };
    
    Statements stmts_;
};

} // namespace Sovereign
