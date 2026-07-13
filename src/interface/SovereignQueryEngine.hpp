/**
 * SovereignQueryEngine.hpp
 *
 * Phase D.2 Batch 2/5: Query & Introspection Engine
 *
 * Provides structured inspection of the sovereign runtime.
 * Supports query language for runtime introspection.
 *
 * Query Examples:
 *   query runtime.health
 *   query graph.critical_path
 *   query swarm.roles
 *   query decisions.recent
 *   query patterns.emerging
 */

#pragma once

#include "../core/SovereignState.hpp"
#include "../emergent/EmergentPatternDetector.hpp"
#include "../autonomy/DecisionTypes.hpp"

#include <string>
#include <vector>
#include <map>
#include <variant>
#include <memory>

namespace Interface {

/**
 * Query result value types
 */
using QueryValue = std::variant<
    std::monostate,  // null
    bool,
    int,
    double,
    std::string,
    std::vector<QueryValue>,
    std::map<std::string, QueryValue>
>;

/**
 * Query result
 */
struct QueryResult {
    bool success{false};
    std::string query;
    QueryValue data;
    std::string errorMessage;
    int64_t executionTimeMs{0};
    
    std::string ToJson() const;
    void Print() const;
};

/**
 * Query context
 */
struct QueryContext {
    Core::SovereignState state;
    std::vector<Emergent::Pattern> patterns;
    std::vector<Autonomy::Decision> decisions;
    std::map<std::string, std::string> metadata;
};

/**
 * Query handler function type
 */
using QueryHandler = std::function<QueryResult(const std::vector<std::string>& path, 
                                                const QueryContext& context)>;

/**
 * Query engine configuration
 */
struct QueryEngineConfig {
    int maxQueryDepth{10};
    int maxResultsPerQuery{1000};
    int queryTimeoutMs{5000};
    bool enableCaching{true};
    int cacheTTLMs{30000};
    
    std::string ToJson() const;
};

/**
 * Sovereign Query Engine
 *
 * Provides structured query capabilities for runtime introspection.
 * Supports dot-notation queries like "runtime.health", "graph.critical_path", etc.
 */
class SovereignQueryEngine {
public:
    SovereignQueryEngine();
    ~SovereignQueryEngine();

    // Disable copy
    SovereignQueryEngine(const SovereignQueryEngine&) = delete;
    SovereignQueryEngine& operator=(const SovereignQueryEngine&) = delete;

    /**
     * Initialize the query engine
     */
    bool Initialize(const QueryEngineConfig& config);

    /**
     * Execute a query
     */
    QueryResult Execute(const std::string& query);

    /**
     * Execute a query with context
     */
    QueryResult Execute(const std::string& query, const QueryContext& context);

    /**
     * Register a custom query handler
     */
    void RegisterHandler(const std::string& path, QueryHandler handler);

    /**
     * Get available queries
     */
    std::vector<std::string> GetAvailableQueries() const;

    /**
     * Get query documentation
     */
    std::string GetQueryDocumentation(const std::string& query) const;

    /**
     * Print status
     */
    void PrintStatus() const;

private:
    QueryEngineConfig config_;
    bool initialized_{false};
    
    // Query handlers
    std::map<std::string, QueryHandler> handlers_;
    
    // Cache
    struct CacheEntry {
        QueryResult result;
        int64_t timestampMs;
    };
    std::map<std::string, CacheEntry> cache_;
    mutable std::mutex cacheMutex_;
    
    // Default handlers
    void RegisterDefaultHandlers();
    
    // Query handlers
    QueryResult HandleRuntimeHealth(const std::vector<std::string>& path, 
                                    const QueryContext& context);
    QueryResult HandleRuntimeStatus(const std::vector<std::string>& path,
                                    const QueryContext& context);
    QueryResult HandleGraphCriticalPath(const std::vector<std::string>& path,
                                        const QueryContext& context);
    QueryResult HandleGraphNodes(const std::vector<std::string>& path,
                                 const QueryContext& context);
    QueryResult HandleSwarmRoles(const std::vector<std::string>& path,
                                 const QueryContext& context);
    QueryResult HandleSwarmWorkers(const std::vector<std::string>& path,
                                   const QueryContext& context);
    QueryResult HandleDecisionsRecent(const std::vector<std::string>& path,
                                      const QueryContext& context);
    QueryResult HandleDecisionsPending(const std::vector<std::string>& path,
                                       const QueryContext& context);
    QueryResult HandlePatternsEmerging(const std::vector<std::string>& path,
                                       const QueryContext& context);
    QueryResult HandlePatternsAnomalies(const std::vector<std::string>& path,
                                        const QueryContext& context);
    QueryResult HandleTelemetryMetrics(const std::vector<std::string>& path,
                                       const QueryContext& context);
    QueryResult HandleAutonomyMode(const std::vector<std::string>& path,
                                   const QueryContext& context);
    
    // Helpers
    std::vector<std::string> ParseQuery(const std::string& query) const;
    QueryValue StateToValue(const Core::SovereignState& state) const;
    bool IsCached(const std::string& query) const;
    QueryResult GetCached(const std::string& query) const;
    void CacheResult(const std::string& query, const QueryResult& result);
    int64_t GetCurrentTimeMs() const;
};

/**
 * Query result formatter
 */
class QueryResultFormatter {
public:
    /**
     * Format result as JSON
     */
    static std::string ToJson(const QueryResult& result);
    
    /**
     * Format result as Markdown
     */
    static std::string ToMarkdown(const QueryResult& result);
    
    /**
     * Format result as plain text
     */
    static std::string ToText(const QueryResult& result);
    
private:
    static std::string ValueToJson(const QueryValue& value, int indent = 0);
    static std::string ValueToText(const QueryValue& value, int indent = 0);
};

/**
 * CLI for testing the query engine
 */
class SovereignQueryEngineCLI {
public:
    static void PrintBanner();
    static void PrintUsage();
    static int Run(int argc, char* argv[]);
    
private:
    static QueryEngineConfig ParseArgs(int argc, char* argv[]);
    static void InteractiveMode(SovereignQueryEngine& engine);
};

} // namespace Interface
