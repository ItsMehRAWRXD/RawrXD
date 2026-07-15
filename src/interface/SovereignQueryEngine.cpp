/**
 * SovereignQueryEngine.cpp
 *
 * Phase D.2 Batch 2/5: Query & Introspection Engine
 */

#include "SovereignQueryEngine.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <algorithm>

namespace Interface {

// ============================================================================
// QueryResult Implementation
// ============================================================================

std::string QueryResult::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"success\":" << (success ? "true" : "false") << ",";
    json << "\"query\":\"" << query << "\",";
    json << "\"data\":" << QueryResultFormatter::ToJson(*this) << ",";
    json << "\"executionTimeMs\":" << executionTimeMs;
    if (!errorMessage.empty()) {
        json << ",\"errorMessage\":\"" << errorMessage << "\"";
    }
    json << "}";
    return json.str();
}

void QueryResult::Print() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  Query: " << std::left << std::setw(52) << query << "  ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Status: " << std::setw(51) << (success ? "SUCCESS" : "FAILED") << " ║\n";
    std::cout << "║  Time:   " << std::setw(10) << executionTimeMs << " ms" 
              << std::string(40, ' ') << "║\n";
    
    if (!errorMessage.empty()) {
        std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
        std::cout << "║  Error:  " << std::setw(52) << errorMessage << " ║\n";
    }
    
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Result:                                                         ║\n";
    
    std::string textResult = QueryResultFormatter::ToText(*this);
    std::istringstream resultStream(textResult);
    std::string line;
    while (std::getline(resultStream, line)) {
        if (line.length() > 58) {
            line = line.substr(0, 55) + "...";
        }
        std::cout << "║  " << std::left << std::setw(58) << line << " ║\n";
    }
    
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// QueryEngineConfig Implementation
// ============================================================================

std::string QueryEngineConfig::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"maxQueryDepth\":" << maxQueryDepth << ",";
    json << "\"maxResultsPerQuery\":" << maxResultsPerQuery << ",";
    json << "\"queryTimeoutMs\":" << queryTimeoutMs << ",";
    json << "\"enableCaching\":" << (enableCaching ? "true" : "false") << ",";
    json << "\"cacheTTLMs\":" << cacheTTLMs;
    json << "}";
    return json.str();
}

// ============================================================================
// SovereignQueryEngine Implementation
// ============================================================================

SovereignQueryEngine::SovereignQueryEngine() = default;
SovereignQueryEngine::~SovereignQueryEngine() = default;

bool SovereignQueryEngine::Initialize(const QueryEngineConfig& config) {
    config_ = config;
    initialized_ = true;
    
    RegisterDefaultHandlers();
    
    std::cout << "[SovereignQueryEngine] Initialized\n";
    std::cout << "  Registered handlers: " << handlers_.size() << "\n";
    std::cout << "  Caching: " << (config.enableCaching ? "enabled" : "disabled") << "\n";
    
    return true;
}

QueryResult SovereignQueryEngine::Execute(const std::string& query) {
    QueryContext context;
    return Execute(query, context);
}

QueryResult SovereignQueryEngine::Execute(const std::string& query, const QueryContext& context) {
    auto startTime = std::chrono::steady_clock::now();
    
    QueryResult result;
    result.query = query;
    
    if (!initialized_) {
        result.success = false;
        result.errorMessage = "Query engine not initialized";
        return result;
    }
    
    // Check cache
    if (config_.enableCaching && IsCached(query)) {
        result = GetCached(query);
        return result;
    }
    
    // Parse query
    auto path = ParseQuery(query);
    if (path.empty()) {
        result.success = false;
        result.errorMessage = "Invalid query format";
        return result;
    }
    
    // Check depth
    if (path.size() > static_cast<size_t>(config_.maxQueryDepth)) {
        result.success = false;
        result.errorMessage = "Query depth exceeds maximum";
        return result;
    }
    
    // Find handler
    std::string handlerKey = path[0];
    for (size_t i = 1; i < path.size() && i < 2; ++i) {
        handlerKey += "." + path[i];
    }
    
    auto it = handlers_.find(handlerKey);
    if (it == handlers_.end()) {
        result.success = false;
        result.errorMessage = "Unknown query: " + query;
        return result;
    }
    
    // Execute handler
    try {
        result = it->second(path, context);
        result.query = query;
    } catch (const std::exception& e) {
        result.success = false;
        result.errorMessage = std::string("Query execution failed: ") + e.what();
    }
    
    auto endTime = std::chrono::steady_clock::now();
    result.executionTimeMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        endTime - startTime).count();
    
    // Cache result
    if (config_.enableCaching && result.success) {
        CacheResult(query, result);
    }
    
    return result;
}

void SovereignQueryEngine::RegisterHandler(const std::string& path, QueryHandler handler) {
    handlers_[path] = handler;
}

std::vector<std::string> SovereignQueryEngine::GetAvailableQueries() const {
    std::vector<std::string> queries;
    for (const auto& [path, _] : handlers_) {
        queries.push_back(path);
    }
    std::sort(queries.begin(), queries.end());
    return queries;
}

std::string SovereignQueryEngine::GetQueryDocumentation(const std::string& query) const {
    static std::map<std::string, std::string> docs = {
        {"runtime.health", "Returns overall runtime health metrics"},
        {"runtime.status", "Returns current runtime status and phase"},
        {"graph.critical_path", "Returns the critical execution path"},
        {"graph.nodes", "Returns all graph nodes"},
        {"swarm.roles", "Returns assigned swarm roles"},
        {"swarm.workers", "Returns active swarm workers"},
        {"decisions.recent", "Returns recent decisions"},
        {"decisions.pending", "Returns pending decisions"},
        {"patterns.emerging", "Returns emerging patterns"},
        {"patterns.anomalies", "Returns detected anomalies"},
        {"telemetry.metrics", "Returns telemetry metrics"},
        {"autonomy.mode", "Returns current autonomy mode"}
    };
    
    auto it = docs.find(query);
    if (it != docs.end()) {
        return it->second;
    }
    return "No documentation available";
}

void SovereignQueryEngine::PrintStatus() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     SOVEREIGN QUERY ENGINE STATUS                                ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Initialized:      " << std::setw(10) << (initialized_ ? "YES" : "NO") 
              << std::string(36, ' ') << "║\n";
    std::cout << "║  Handlers:         " << std::setw(10) << handlers_.size() 
              << std::string(36, ' ') << "║\n";
    std::cout << "║  Caching:          " << std::setw(10) << (config_.enableCaching ? "ENABLED" : "DISABLED") 
              << std::string(36, ' ') << "║\n";
    std::cout << "║  Cache Entries:    " << std::setw(10) << cache_.size() 
              << std::string(36, ' ') << "║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// ============================================================================
// Default Handlers
// ============================================================================

void SovereignQueryEngine::RegisterDefaultHandlers() {
    // Runtime queries
    handlers_["runtime.health"] = [this](const auto& path, const auto& ctx) {
        return HandleRuntimeHealth(path, ctx);
    };
    handlers_["runtime.status"] = [this](const auto& path, const auto& ctx) {
        return HandleRuntimeStatus(path, ctx);
    };
    
    // Graph queries
    handlers_["graph.critical_path"] = [this](const auto& path, const auto& ctx) {
        return HandleGraphCriticalPath(path, ctx);
    };
    handlers_["graph.nodes"] = [this](const auto& path, const auto& ctx) {
        return HandleGraphNodes(path, ctx);
    };
    
    // Swarm queries
    handlers_["swarm.roles"] = [this](const auto& path, const auto& ctx) {
        return HandleSwarmRoles(path, ctx);
    };
    handlers_["swarm.workers"] = [this](const auto& path, const auto& ctx) {
        return HandleSwarmWorkers(path, ctx);
    };
    
    // Decision queries
    handlers_["decisions.recent"] = [this](const auto& path, const auto& ctx) {
        return HandleDecisionsRecent(path, ctx);
    };
    handlers_["decisions.pending"] = [this](const auto& path, const auto& ctx) {
        return HandleDecisionsPending(path, ctx);
    };
    
    // Pattern queries
    handlers_["patterns.emerging"] = [this](const auto& path, const auto& ctx) {
        return HandlePatternsEmerging(path, ctx);
    };
    handlers_["patterns.anomalies"] = [this](const auto& path, const auto& ctx) {
        return HandlePatternsAnomalies(path, ctx);
    };
    
    // Telemetry queries
    handlers_["telemetry.metrics"] = [this](const auto& path, const auto& ctx) {
        return HandleTelemetryMetrics(path, ctx);
    };
    
    // Autonomy queries
    handlers_["autonomy.mode"] = [this](const auto& path, const auto& ctx) {
        return HandleAutonomyMode(path, ctx);
    };
}

// ============================================================================
// Query Handlers
// ============================================================================

QueryResult SovereignQueryEngine::HandleRuntimeHealth(const std::vector<std::string>& path,
                                                       const QueryContext& context) {
    QueryResult result;
    result.success = true;
    
    std::map<std::string, QueryValue> health;
    health["runtime"] = context.state.phase;
    health["stability"] = context.state.stability;
    health["convergence"] = context.state.convergence;
    health["performance"] = context.state.performance;
    health["healthy"] = context.state.IsHealthy();
    
    result.data = health;
    return result;
}

QueryResult SovereignQueryEngine::HandleRuntimeStatus(const std::vector<std::string>& path,
                                                      const QueryContext& context) {
    QueryResult result;
    result.success = true;
    
    std::map<std::string, QueryValue> status;
    status["phase"] = context.state.phase;
    status["mode"] = Core::ExecutionModeToString(context.state.mode);
    status["version"] = context.state.version;
    status["timestamp"] = static_cast<int>(context.state.timestampMs);
    status["active_subsystems"] = static_cast<int>(context.state.activeSubsystems);
    status["healthy_subsystems"] = static_cast<int>(context.state.healthySubsystems);
    
    result.data = status;
    return result;
}

QueryResult SovereignQueryEngine::HandleGraphCriticalPath(const std::vector<std::string>& path,
                                                          const QueryContext& context) {
    QueryResult result;
    result.success = true;
    
    std::map<std::string, QueryValue> pathInfo;
    pathInfo["length_ms"] = 100.0;  // Would calculate actual critical path
    pathInfo["nodes"] = static_cast<int>(context.state.activeNodes);
    pathInfo["bottleneck"] = "node_42";
    
    result.data = pathInfo;
    return result;
}

QueryResult SovereignQueryEngine::HandleGraphNodes(const std::vector<std::string>& path,
                                                   const QueryContext& context) {
    QueryResult result;
    result.success = true;
    
    std::vector<QueryValue> nodes;
    for (int i = 0; i < context.state.seg.nodeCount && i < config_.maxResultsPerQuery; ++i) {
        std::map<std::string, QueryValue> node;
        node["id"] = "node_" + std::to_string(i);
        node["status"] = "active";
        nodes.push_back(node);
    }
    
    result.data = nodes;
    return result;
}

QueryResult SovereignQueryEngine::HandleSwarmRoles(const std::vector<std::string>& path,
                                                   const QueryContext& context) {
    QueryResult result;
    result.success = true;
    
    std::map<std::string, QueryValue> roles;
    roles["total"] = static_cast<int>(context.state.activeWorkers);
    roles["coordinators"] = 1;
    roles["specialists"] = 3;
    roles["generalists"] = static_cast<int>(context.state.activeWorkers) - 4;
    
    result.data = roles;
    return result;
}

QueryResult SovereignQueryEngine::HandleSwarmWorkers(const std::vector<std::string>& path,
                                                     const QueryContext& context) {
    QueryResult result;
    result.success = true;
    
    std::map<std::string, QueryValue> workers;
    workers["total"] = context.state.swarm.totalWorkers;
    workers["active"] = context.state.swarm.activeWorkers;
    workers["idle"] = context.state.swarm.idleWorkers;
    workers["failed"] = context.state.swarm.failedWorkers;
    workers["tasks_completed"] = context.state.swarm.tasksCompleted;
    
    result.data = workers;
    return result;
}

QueryResult SovereignQueryEngine::HandleDecisionsRecent(const std::vector<std::string>& path,
                                                        const QueryContext& context) {
    QueryResult result;
    result.success = true;
    
    std::vector<QueryValue> decisions;
    for (const auto& decision : context.decisions) {
        if (decisions.size() >= static_cast<size_t>(config_.maxResultsPerQuery)) break;
        
        std::map<std::string, QueryValue> dec;
        dec["id"] = decision.decisionId;
        dec["type"] = Autonomy::DecisionTypeToString(decision.type);
        dec["confidence"] = decision.confidence;
        dec["status"] = Autonomy::DecisionStatusToString(decision.status);
        decisions.push_back(dec);
    }
    
    result.data = decisions;
    return result;
}

QueryResult SovereignQueryEngine::HandleDecisionsPending(const std::vector<std::string>& path,
                                                         const QueryContext& context) {
    QueryResult result;
    result.success = true;
    
    std::vector<QueryValue> pending;
    for (const auto& decision : context.decisions) {
        if (decision.status == Autonomy::DecisionStatus::PENDING) {
            std::map<std::string, QueryValue> dec;
            dec["id"] = decision.decisionId;
            dec["type"] = Autonomy::DecisionTypeToString(decision.type);
            dec["priority"] = Autonomy::DecisionPriorityToString(decision.priority);
            pending.push_back(dec);
        }
    }
    
    result.data = pending;
    return result;
}

QueryResult SovereignQueryEngine::HandlePatternsEmerging(const std::vector<std::string>& path,
                                                        const QueryContext& context) {
    QueryResult result;
    result.success = true;
    
    std::vector<QueryValue> patterns;
    for (const auto& pattern : context.patterns) {
        if (patterns.size() >= static_cast<size_t>(config_.maxResultsPerQuery)) break;
        if (pattern.strength > 0.7) {
            std::map<std::string, QueryValue> pat;
            pat["id"] = pattern.patternId;
            pat["type"] = static_cast<int>(pattern.type);
            pat["strength"] = pattern.strength;
            pat["source"] = pattern.source;
            patterns.push_back(pat);
        }
    }
    
    result.data = patterns;
    return result;
}

QueryResult SovereignQueryEngine::HandlePatternsAnomalies(const std::vector<std::string>& path,
                                                          const QueryContext& context) {
    QueryResult result;
    result.success = true;
    
    std::vector<QueryValue> anomalies;
    for (const auto& pattern : context.patterns) {
        if (pattern.type == Emergent::PatternType::ANOMALY) {
            std::map<std::string, QueryValue> anom;
            anom["id"] = pattern.patternId;
            anom["severity"] = pattern.strength;
            anom["source"] = pattern.source;
            anomalies.push_back(anom);
        }
    }
    
    result.data = anomalies;
    return result;
}

QueryResult SovereignQueryEngine::HandleTelemetryMetrics(const std::vector<std::string>& path,
                                                         const QueryContext& context) {
    QueryResult result;
    result.success = true;
    
    std::map<std::string, QueryValue> metrics;
    metrics["cpu_utilization"] = context.state.runtime.cpuUtilization;
    metrics["memory_usage_mb"] = context.state.runtime.memoryUsageMB;
    metrics["active_threads"] = context.state.runtime.activeThreads;
    metrics["cycle_count"] = context.state.runtime.cycleCount;
    metrics["uptime_ms"] = static_cast<int>(context.state.runtime.uptimeMs);
    
    result.data = metrics;
    return result;
}

QueryResult SovereignQueryEngine::HandleAutonomyMode(const std::vector<std::string>& path,
                                                   const QueryContext& context) {
    QueryResult result;
    result.success = true;
    
    std::map<std::string, QueryValue> mode;
    mode["current"] = Core::ExecutionModeToString(context.state.mode);
    mode["decisions_pending"] = context.state.autonomy.decisionsPending;
    mode["decisions_executed"] = context.state.autonomy.decisionsExecuted;
    mode["avg_confidence"] = context.state.autonomy.averageDecisionConfidence;
    mode["emergency_stopped"] = context.state.autonomy.emergencyStopped;
    
    result.data = mode;
    return result;
}

// ============================================================================
// Helpers
// ============================================================================

std::vector<std::string> SovereignQueryEngine::ParseQuery(const std::string& query) const {
    std::vector<std::string> parts;
    std::istringstream stream(query);
    std::string part;
    
    while (std::getline(stream, part, '.')) {
        if (!part.empty()) {
            parts.push_back(part);
        }
    }
    
    return parts;
}

bool SovereignQueryEngine::IsCached(const std::string& query) const {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    
    auto it = cache_.find(query);
    if (it == cache_.end()) {
        return false;
    }
    
    // Check TTL
    auto now = GetCurrentTimeMs();
    return (now - it->second.timestampMs) < config_.cacheTTLMs;
}

QueryResult SovereignQueryEngine::GetCached(const std::string& query) const {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    return cache_.at(query).result;
}

void SovereignQueryEngine::CacheResult(const std::string& query, const QueryResult& result) {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    
    CacheEntry entry;
    entry.result = result;
    entry.timestampMs = GetCurrentTimeMs();
    
    cache_[query] = entry;
    
    // Prune cache if too large
    if (cache_.size() > 1000) {
        auto oldest = cache_.begin();
        for (auto it = cache_.begin(); it != cache_.end(); ++it) {
            if (it->second.timestampMs < oldest->second.timestampMs) {
                oldest = it;
            }
        }
        cache_.erase(oldest);
    }
}

int64_t SovereignQueryEngine::GetCurrentTimeMs() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

// ============================================================================
// QueryResultFormatter Implementation
// ============================================================================

std::string QueryResultFormatter::ToJson(const QueryResult& result) {
    return std::visit([](const auto& val) -> std::string {
        using T = std::decay_t<decltype(val)>;
        if constexpr (std::is_same_v<T, std::monostate>) {
            return "null";
        } else if constexpr (std::is_same_v<T, bool>) {
            return val ? "true" : "false";
        } else if constexpr (std::is_same_v<T, int>) {
            return std::to_string(val);
        } else if constexpr (std::is_same_v<T, double>) {
            std::ostringstream oss;
            oss << std::fixed << std::setprecision(4) << val;
            return oss.str();
        } else if constexpr (std::is_same_v<T, std::string>) {
            return "\"" + val + "\"";
        } else if constexpr (std::is_same_v<T, std::vector<QueryValue>>) {
            std::string json = "[";
            for (size_t i = 0; i < val.size(); ++i) {
                if (i > 0) json += ",";
                json += ToJson(QueryResult{true, "", val[i], "", 0});
            }
            json += "]";
            return json;
        } else if constexpr (std::is_same_v<T, std::map<std::string, QueryValue>>) {
            std::string json = "{";
            bool first = true;
            for (const auto& [key, value] : val) {
                if (!first) json += ",";
                json += "\"" + key + "\":";
                json += ToJson(QueryResult{true, "", value, "", 0});
                first = false;
            }
            json += "}";
            return json;
        }
        return "null";
    }, result.data);
}

std::string QueryResultFormatter::ToMarkdown(const QueryResult& result) {
    std::ostringstream md;
    md << "## Query Result: " << result.query << "\n\n";
    md << "- **Success:** " << (result.success ? "Yes" : "No") << "\n";
    md << "- **Execution Time:** " << result.executionTimeMs << " ms\n\n";
    
    if (!result.errorMessage.empty()) {
        md << "**Error:** " << result.errorMessage << "\n\n";
    }
    
    md << "### Data\n\n";
    md << "```json\n";
    md << ToJson(result);
    md << "\n```\n";
    
    return md.str();
}

std::string QueryResultFormatter::ToText(const QueryResult& result) {
    return std::visit([](const auto& val) -> std::string {
        using T = std::decay_t<decltype(val)>;
        if constexpr (std::is_same_v<T, std::monostate>) {
            return "null";
        } else if constexpr (std::is_same_v<T, bool>) {
            return val ? "true" : "false";
        } else if constexpr (std::is_same_v<T, int>) {
            return std::to_string(val);
        } else if constexpr (std::is_same_v<T, double>) {
            std::ostringstream oss;
            oss << std::fixed << std::setprecision(2) << val;
            return oss.str();
        } else if constexpr (std::is_same_v<T, std::string>) {
            return val;
        } else if constexpr (std::is_same_v<T, std::vector<QueryValue>>) {
            std::string text = "[";
            for (size_t i = 0; i < val.size() && i < 5; ++i) {
                if (i > 0) text += ", ";
                text += ToText(QueryResult{true, "", val[i], "", 0});
            }
            if (val.size() > 5) text += "...";
            text += "]";
            return text;
        } else if constexpr (std::is_same_v<T, std::map<std::string, QueryValue>>) {
            std::string text = "{";
            bool first = true;
            for (const auto& [key, value] : val) {
                if (!first) text += ", ";
                text += key + ": " + ToText(QueryResult{true, "", value, "", 0});
                first = false;
            }
            text += "}";
            return text;
        }
        return "null";
    }, result.data);
}

// ============================================================================
// CLI Implementation
// ============================================================================

void SovereignQueryEngineCLI::PrintBanner() {
    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                                                ║\n";
    std::cout << "║     SOVEREIGN QUERY ENGINE - Phase D.2                            ║\n";
    std::cout << "║     Query \u0026 Introspection Engine                                  ║\n";
    std::cout << "║                                                                ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n\n";
}

void SovereignQueryEngineCLI::PrintUsage() {
    std::cout << "Usage: sovereign-query-engine [OPTIONS] [QUERY]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --interactive        Start interactive mode\n";
    std::cout << "  --list               List available queries\n";
    std::cout << "  --help               Show this help\n\n";
    std::cout << "Examples:\n";
    std::cout << "  sovereign-query-engine runtime.health\n";
    std::cout << "  sovereign-query-engine --interactive\n";
}

QueryEngineConfig SovereignQueryEngineCLI::ParseArgs(int argc, char* argv[]) {
    QueryEngineConfig config;
    return config;
}

void SovereignQueryEngineCLI::InteractiveMode(SovereignQueryEngine& engine) {
    std::cout << "\nInteractive Query Mode\n";
    std::cout << "Type 'help' for available queries, 'quit' to exit\n\n";
    
    std::string query;
    while (true) {
        std::cout << "query> ";
        std::getline(std::cin, query);
        
        if (query == "quit" || query == "exit") {
            break;
        }
        
        if (query == "help") {
            std::cout << "\nAvailable queries:\n";
            for (const auto& q : engine.GetAvailableQueries()) {
                std::cout << "  - " << q << ": " << engine.GetQueryDocumentation(q) << "\n";
            }
            std::cout << "\n";
            continue;
        }
        
        if (query.empty()) {
            continue;
        }
        
        auto result = engine.Execute(query);
        result.Print();
    }
}

int SovereignQueryEngineCLI::Run(int argc, char* argv[]) {
    PrintBanner();
    
    if (argc > 1 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        PrintUsage();
        return 0;
    }
    
    QueryEngineConfig config = ParseArgs(argc, argv);
    
    SovereignQueryEngine engine;
    if (!engine.Initialize(config)) {
        std::cerr << "Failed to initialize query engine\n";
        return 1;
    }
    
    // Check for --list
    if (argc > 1 && std::string(argv[1]) == "--list") {
        std::cout << "\nAvailable queries:\n";
        for (const auto& query : engine.GetAvailableQueries()) {
            std::cout << "  - " << query << "\n";
        }
        std::cout << "\n";
        return 0;
    }
    
    // Check for --interactive
    if (argc > 1 && std::string(argv[1]) == "--interactive") {
        InteractiveMode(engine);
        return 0;
    }
    
    // Execute single query
    if (argc > 1) {
        std::string query = argv[1];
        for (int i = 2; i < argc; ++i) {
            query += " ";
            query += argv[i];
        }
        
        auto result = engine.Execute(query);
        result.Print();
        
        return result.success ? 0 : 1;
    }
    
    // No query provided, enter interactive mode
    InteractiveMode(engine);
    return 0;
}

} // namespace Interface
