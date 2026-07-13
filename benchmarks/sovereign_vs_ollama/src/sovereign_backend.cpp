// Sovereign Backend Adapter Implementation
// Copyright (c) 2026 RawrXD Team

#include "sovereign_backend.hpp"
#include <sstream>
#include <iomanip>
#include <chrono>

namespace rawrxd::benchmark {

// ============================================================================
// Sovereign API Types Implementation
// ============================================================================

std::string SovereignGenerateRequest::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"prompt\":\"" << EscapeJsonString(prompt) << "\",";
    oss << "\"model\":\"" << EscapeJsonString(model) << "\",";
    oss << "\"max_tokens\":" << max_tokens << ",";
    oss << "\"temperature\":" << temperature << ",";
    oss << "\"seed\":" << seed << ",";
    oss << "\"stream\":" << (stream ? "true" : "false");
    oss << "}";
    return oss.str();
}

SovereignGenerateResponse SovereignGenerateResponse::FromJson(const std::string& json) {
    SovereignGenerateResponse response;
    
    // Simple JSON parsing (in production, use a proper JSON library)
    auto GetString = [&](const std::string& key) -> std::string {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return "";
        pos = json.find(":", pos);
        if (pos == std::string::npos) return "";
        pos = json.find_first_of("\"", pos);
        if (pos == std::string::npos) return "";
        size_t end = json.find_first_of("\"", pos + 1);
        if (end == std::string::npos) return "";
        return json.substr(pos + 1, end - pos - 1);
    };
    
    auto GetInt = [&](const std::string& key) -> int {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return 0;
        pos = json.find(":", pos);
        if (pos == std::string::npos) return 0;
        pos = json.find_first_of("0123456789-", pos);
        if (pos == std::string::npos) return 0;
        size_t end = json.find_first_of(",}", pos);
        if (end == std::string::npos) return 0;
        try {
            return std::stoi(json.substr(pos, end - pos));
        } catch (...) {
            return 0;
        }
    };
    
    auto GetDouble = [&](const std::string& key) -> double {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return 0.0;
        pos = json.find(":", pos);
        if (pos == std::string::npos) return 0.0;
        pos = json.find_first_of("0123456789-.", pos);
        if (pos == std::string::npos) return 0.0;
        size_t end = json.find_first_of(",}", pos);
        if (end == std::string::npos) return 0.0;
        try {
            return std::stod(json.substr(pos, end - pos));
        } catch (...) {
            return 0.0;
        }
    };
    
    response.text = GetString("text");
    response.tokens_generated = GetInt("tokens_generated");
    response.generation_time_ms = GetDouble("generation_time_ms");
    response.tokens_per_second = GetDouble("tokens_per_second");
    response.success = json.find("\"success\":true") != std::string::npos ||
                       json.find("\"success\": true") != std::string::npos;
    
    if (!response.success) {
        response.error_message = GetString("error");
    }
    
    return response;
}

std::string SovereignAgentRequest::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"role\":\"" << EscapeJsonString(role) << "\",";
    oss << "\"context\":\"" << EscapeJsonString(context) << "\",";
    oss << "\"capabilities\":{";
    bool first = true;
    for (const auto& [key, value] : capabilities) {
        if (!first) oss << ",";
        first = false;
        oss << "\"" << EscapeJsonString(key) << "\":\"" << EscapeJsonString(value) << "\"";
    }
    oss << "}}";
    return oss.str();
}

SovereignAgentResponse SovereignAgentResponse::FromJson(const std::string& json) {
    SovereignAgentResponse response;
    
    auto GetString = [&](const std::string& key) -> std::string {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return "";
        pos = json.find(":", pos);
        if (pos == std::string::npos) return "";
        pos = json.find_first_of("\"", pos);
        if (pos == std::string::npos) return "";
        size_t end = json.find_first_of("\"", pos + 1);
        if (end == std::string::npos) return "";
        return json.substr(pos + 1, end - pos - 1);
    };
    
    auto GetDouble = [&](const std::string& key) -> double {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return 0.0;
        pos = json.find(":", pos);
        if (pos == std::string::npos) return 0.0;
        pos = json.find_first_of("0123456789-.", pos);
        if (pos == std::string::npos) return 0.0;
        size_t end = json.find_first_of(",}", pos);
        if (end == std::string::npos) return 0.0;
        try {
            return std::stod(json.substr(pos, end - pos));
        } catch (...) {
            return 0.0;
        }
    };
    
    response.agent_id = GetString("agent_id");
    response.status = GetString("status");
    response.spawn_time_ms = GetDouble("spawn_time_ms");
    response.success = json.find("\"success\":true") != std::string::npos ||
                       json.find("\"success\": true") != std::string::npos;
    
    if (!response.success) {
        response.error_message = GetString("error");
    }
    
    return response;
}

std::string SovereignSwarmRequest::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"count\":" << count << ",";
    oss << "\"task\":\"" << EscapeJsonString(task) << "\",";
    oss << "\"coordination_strategy\":\"" << EscapeJsonString(coordination_strategy) << "\"";
    oss << "}";
    return oss.str();
}

SovereignSwarmResponse SovereignSwarmResponse::FromJson(const std::string& json) {
    SovereignSwarmResponse response;
    
    auto GetString = [&](const std::string& key) -> std::string {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return "";
        pos = json.find(":", pos);
        if (pos == std::string::npos) return "";
        pos = json.find_first_of("\"", pos);
        if (pos == std::string::npos) return "";
        size_t end = json.find_first_of("\"", pos + 1);
        if (end == std::string::npos) return "";
        return json.substr(pos + 1, end - pos - 1);
    };
    
    auto GetDouble = [&](const std::string& key) -> double {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return 0.0;
        pos = json.find(":", pos);
        if (pos == std::string::npos) return 0.0;
        pos = json.find_first_of("0123456789-.", pos);
        if (pos == std::string::npos) return 0.0;
        size_t end = json.find_first_of(",}", pos);
        if (end == std::string::npos) return 0.0;
        try {
            return std::stod(json.substr(pos, end - pos));
        } catch (...) {
            return 0.0;
        }
    };
    
    response.swarm_id = GetString("swarm_id");
    response.spawn_time_ms = GetDouble("spawn_time_ms");
    response.success = json.find("\"success\":true") != std::string::npos ||
                       json.find("\"success\": true") != std::string::npos;
    
    // Parse agent_ids array
    size_t agents_pos = json.find("\"agent_ids\"");
    if (agents_pos != std::string::npos) {
        size_t arr_start = json.find("[", agents_pos);
        size_t arr_end = json.find("]", arr_start);
        if (arr_start != std::string::npos && arr_end != std::string::npos) {
            std::string arr_content = json.substr(arr_start + 1, arr_end - arr_start - 1);
            std::istringstream iss(arr_content);
            std::string token;
            while (std::getline(iss, token, ',')) {
                // Trim whitespace and quotes
                size_t start = token.find_first_of("\"");
                size_t end = token.find_last_of("\"");
                if (start != std::string::npos && end != std::string::npos && end > start) {
                    response.agent_ids.push_back(token.substr(start + 1, end - start - 1));
                }
            }
        }
    }
    
    if (!response.success) {
        response.error_message = GetString("error");
    }
    
    return response;
}

std::string SovereignSEGRequest::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"plan\":\"" << EscapeJsonString(plan) << "\",";
    oss << "\"parameters\":{";
    bool first = true;
    for (const auto& [key, value] : parameters) {
        if (!first) oss << ",";
        first = false;
        oss << "\"" << EscapeJsonString(key) << "\":\"" << EscapeJsonString(value) << "\"";
    }
    oss << "}}";
    return oss.str();
}

SovereignSEGResponse SovereignSEGResponse::FromJson(const std::string& json) {
    SovereignSEGResponse response;
    
    auto GetString = [&](const std::string& key) -> std::string {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return "";
        pos = json.find(":", pos);
        if (pos == std::string::npos) return "";
        pos = json.find_first_of("\"", pos);
        if (pos == std::string::npos) return "";
        size_t end = json.find_first_of("\"", pos + 1);
        if (end == std::string::npos) return "";
        return json.substr(pos + 1, end - pos - 1);
    };
    
    auto GetInt = [&](const std::string& key) -> int {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return 0;
        pos = json.find(":", pos);
        if (pos == std::string::npos) return 0;
        pos = json.find_first_of("0123456789-", pos);
        if (pos == std::string::npos) return 0;
        size_t end = json.find_first_of(",}", pos);
        if (end == std::string::npos) return 0;
        try {
            return std::stoi(json.substr(pos, end - pos));
        } catch (...) {
            return 0;
        }
    };
    
    auto GetDouble = [&](const std::string& key) -> double {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return 0.0;
        pos = json.find(":", pos);
        if (pos == std::string::npos) return 0.0;
        pos = json.find_first_of("0123456789-.", pos);
        if (pos == std::string::npos) return 0.0;
        size_t end = json.find_first_of(",}", pos);
        if (end == std::string::npos) return 0.0;
        try {
            return std::stod(json.substr(pos, end - pos));
        } catch (...) {
            return 0.0;
        }
    };
    
    response.graph_id = GetString("graph_id");
    response.graph_json = GetString("graph_json");
    response.build_time_ms = GetDouble("build_time_ms");
    response.node_count = GetInt("node_count");
    response.edge_count = GetInt("edge_count");
    response.success = json.find("\"success\":true") != std::string::npos ||
                       json.find("\"success\": true") != std::string::npos;
    
    if (!response.success) {
        response.error_message = GetString("error");
    }
    
    return response;
}

std::string SovereignDecisionRequest::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"context\":\"" << EscapeJsonString(context) << "\",";
    oss << "\"options\":[";
    bool first = true;
    for (const auto& opt : options) {
        if (!first) oss << ",";
        first = false;
        oss << "\"" << EscapeJsonString(opt) << "\"";
    }
    oss << "],";
    oss << "\"weights\":{";
    first = true;
    for (const auto& [key, value] : weights) {
        if (!first) oss << ",";
        first = false;
        oss << "\"" << EscapeJsonString(key) << "\":" << value;
    }
    oss << "}}";
    return oss.str();
}

SovereignDecisionResponse SovereignDecisionResponse::FromJson(const std::string& json) {
    SovereignDecisionResponse response;
    
    auto GetString = [&](const std::string& key) -> std::string {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return "";
        pos = json.find(":", pos);
        if (pos == std::string::npos) return "";
        pos = json.find_first_of("\"", pos);
        if (pos == std::string::npos) return "";
        size_t end = json.find_first_of("\"", pos + 1);
        if (end == std::string::npos) return "";
        return json.substr(pos + 1, end - pos - 1);
    };
    
    auto GetDouble = [&](const std::string& key) -> double {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return 0.0;
        pos = json.find(":", pos);
        if (pos == std::string::npos) return 0.0;
        pos = json.find_first_of("0123456789-.", pos);
        if (pos == std::string::npos) return 0.0;
        size_t end = json.find_first_of(",}", pos);
        if (end == std::string::npos) return 0.0;
        try {
            return std::stod(json.substr(pos, end - pos));
        } catch (...) {
            return 0.0;
        }
    };
    
    response.selected_option = GetString("selected_option");
    response.confidence = GetDouble("confidence");
    response.reasoning = GetString("reasoning");
    response.decision_time_ms = GetDouble("decision_time_ms");
    response.success = json.find("\"success\":true") != std::string::npos ||
                       json.find("\"success\": true") != std::string::npos;
    
    if (!response.success) {
        response.error_message = GetString("error");
    }
    
    return response;
}

SovereignHealthResponse SovereignHealthResponse::FromJson(const std::string& json) {
    SovereignHealthResponse response;
    
    auto GetString = [&](const std::string& key) -> std::string {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return "";
        pos = json.find(":", pos);
        if (pos == std::string::npos) return "";
        pos = json.find_first_of("\"", pos);
        if (pos == std::string::npos) return "";
        size_t end = json.find_first_of("\"", pos + 1);
        if (end == std::string::npos) return "";
        return json.substr(pos + 1, end - pos - 1);
    };
    
    auto GetDouble = [&](const std::string& key) -> double {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return 0.0;
        pos = json.find(":", pos);
        if (pos == std::string::npos) return 0.0;
        pos = json.find_first_of("0123456789-.", pos);
        if (pos == std::string::npos) return 0.0;
        size_t end = json.find_first_of(",}", pos);
        if (end == std::string::npos) return 0.0;
        try {
            return std::stod(json.substr(pos, end - pos));
        } catch (...) {
            return 0.0;
        }
    };
    
    response.healthy = json.find("\"healthy\":true") != std::string::npos ||
                     json.find("\"healthy\": true") != std::string::npos;
    response.version = GetString("version");
    response.uptime_seconds = GetDouble("uptime_seconds");
    
    // Parse capabilities
    size_t caps_pos = json.find("\"capabilities\"");
    if (caps_pos != std::string::npos) {
        size_t obj_start = json.find("{", caps_pos);
        size_t obj_end = json.find("}", obj_start);
        if (obj_start != std::string::npos && obj_end != std::string::npos) {
            std::string caps_content = json.substr(obj_start + 1, obj_end - obj_start - 1);
            // Simple key-value parsing
            std::istringstream iss(caps_content);
            std::string pair;
            while (std::getline(iss, pair, ',')) {
                size_t colon = pair.find(':');
                if (colon != std::string::npos) {
                    std::string key = pair.substr(0, colon);
                    std::string value = pair.substr(colon + 1);
                    // Trim quotes
                    key.erase(std::remove(key.begin(), key.end(), '"'), key.end());
                    value.erase(std::remove(value.begin(), value.end(), '"'), value.end());
                    response.capabilities[key] = value;
                }
            }
        }
    }
    
    return response;
}

// ============================================================================
// Sovereign Backend Adapter Implementation
// ============================================================================

SovereignBackendAdapter::SovereignBackendAdapter() = default;
SovereignBackendAdapter::~SovereignBackendAdapter() {
    Shutdown();
}

bool SovereignBackendAdapter::Initialize(const BenchmarkConfig& config) {
    if (initialized_) return true;
    
    // Parse configuration
    if (!config.backend_endpoint.empty()) {
        endpoint_ = config.backend_endpoint;
    }
    if (!config.model_name.empty()) {
        model_name_ = config.model_name;
    }
    
    // Initialize HTTP client
    http_client_ = std::make_unique<HttpClient>();
    if (!http_client_>Initialize()) {
        return false;
    }
    
    http_client_>SetUserAgent("RawrXD-Benchmark/1.0");
    http_client_>SetDefaultTimeout(5000, 30000, 60000);  // 5s connect, 30s read, 60s total
    http_client_>SetRetryPolicy(3, 1000, true);  // 3 retries, 1s base, exponential
    http_client_>EnableConnectionPool(10);
    
    initialized_ = true;
    return true;
}

void SovereignBackendAdapter::Shutdown() {
    if (!initialized_) return;
    
    http_client_>Shutdown();
    http_client_.reset();
    
    initialized_ = false;
}

std::string SovereignBackendAdapter::Generate(const std::string& prompt, int max_tokens) {
    if (!initialized_) {
        return "";
    }
    
    SovereignGenerateRequest req;
    req.prompt = prompt;
    req.model = model_name_;
    req.max_tokens = max_tokens > 0 ? max_tokens : default_max_tokens_;
    req.temperature = default_temperature_;
    req.seed = default_seed_;
    req.stream = false;
    
    std::string url = BuildUrl("/api/generate");
    std::string json_body = req.ToJson();
    
    auto start = Clock::now();
    HttpResponse http_resp = http_client_>PostJson(url, json_body);
    auto end = Clock::now();
    
    double latency_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    if (!http_resp.IsSuccess()) {
        UpdateStats(false, latency_ms);
        return "";
    }
    
    SovereignGenerateResponse resp = SovereignGenerateResponse::FromJson(http_resp.body);
    
    if (!resp.success) {
        UpdateStats(false, latency_ms);
        return "";
    }
    
    last_latency_ms_ = latency_ms;
    last_tokens_per_sec_ = resp.tokens_per_second;
    
    UpdateStats(true, latency_ms, resp.tokens_generated);
    
    return resp.text;
}

std::string SovereignBackendAdapter::SpawnAgent(const std::string& role, 
                                               const std::string& context) {
    if (!initialized_) return "";
    
    SovereignAgentRequest req;
    req.role = role;
    req.context = context;
    req.capabilities["type"] = "benchmark_agent";
    
    std::string url = BuildUrl("/api/agent/spawn");
    std::string json_body = req.ToJson();
    
    HttpResponse http_resp = http_client_>PostJson(url, json_body);
    
    if (!http_resp.IsSuccess()) {
        return "";
    }
    
    SovereignAgentResponse resp = SovereignAgentResponse::FromJson(http_resp.body);
    
    if (!resp.success) {
        return "";
    }
    
    active_agents_[resp.agent_id] = role;
    return resp.agent_id;
}

bool SovereignBackendAdapter::DestroyAgent(const std::string& agent_id) {
    if (!initialized_) return false;
    
    std::string url = BuildUrl("/api/agent/destroy");
    std::string json_body = "{\"agent_id\":\"" + EscapeJsonString(agent_id) + "\"}";
    
    HttpResponse http_resp = http_client_>PostJson(url, json_body);
    
    if (http_resp.IsSuccess()) {
        active_agents_.erase(agent_id);
        return true;
    }
    
    return false;
}

std::vector<std::string> SovereignBackendAdapter::ListAgents() {
    std::vector<std::string> agents;
    for (const auto& [id, role] : active_agents_) {
        agents.push_back(id);
    }
    return agents;
}

std::vector<std::string> SovereignBackendAdapter::SpawnSwarm(int count, 
                                                              const std::string& task) {
    if (!initialized_) return {};
    
    SovereignSwarmRequest req;
    req.count = count;
    req.task = task;
    
    std::string url = BuildUrl("/api/swarm/spawn");
    std::string json_body = req.ToJson();
    
    HttpResponse http_resp = http_client_>PostJson(url, json_body);
    
    if (!http_resp.IsSuccess()) {
        return {};
    }
    
    SovereignSwarmResponse resp = SovereignSwarmResponse::FromJson(http_resp.body);
    
    if (!resp.success) {
        return {};
    }
    
    // Track spawned agents
    for (const auto& agent_id : resp.agent_ids) {
        active_agents_[agent_id] = "swarm_member";
    }
    
    return resp.agent_ids;
}

std::vector<std::string> SovereignBackendAdapter::ExecuteSwarm(
    const std::vector<std::string>& agents, const std::string& task) {
    
    if (!initialized_ || agents.empty()) return {};
    
    // Build request
    std::ostringstream oss;
    oss << "{";
    oss << "\"agent_ids\":[";
    for (size_t i = 0; i < agents.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << EscapeJsonString(agents[i]) << "\"";
    }
    oss << "],";
    oss << "\"task\":\"" << EscapeJsonString(task) << "\"";
    oss << "}";
    
    std::string url = BuildUrl("/api/swarm/execute");
    std::string json_body = oss.str();
    
    HttpResponse http_resp = http_client_>PostJson(url, json_body);
    
    if (!http_resp.IsSuccess()) {
        return {};
    }
    
    // Parse results
    std::vector<std::string> results;
    size_t results_pos = http_resp.body.find("\"results\"");
    if (results_pos != std::string::npos) {
        size_t arr_start = http_resp.body.find("[", results_pos);
        size_t arr_end = http_resp.body.find("]", arr_start);
        if (arr_start != std::string::npos && arr_end != std::string::npos) {
            std::string arr_content = http_resp.body.substr(arr_start + 1, arr_end - arr_start - 1);
            std::istringstream iss(arr_content);
            std::string token;
            while (std::getline(iss, token, ',')) {
                size_t start = token.find_first_of("\"");
                size_t end = token.find_last_of("\"");
                if (start != std::string::npos && end != std::string::npos && end > start) {
                    results.push_back(token.substr(start + 1, end - start - 1));
                }
            }
        }
    }
    
    return results;
}

std::string SovereignBackendAdapter::CreateExecutionGraph(const std::string& plan) {
    if (!initialized_) return "";
    
    SovereignSEGRequest req;
    req.plan = plan;
    
    std::string url = BuildUrl("/api/seg/create");
    std::string json_body = req.ToJson();
    
    HttpResponse http_resp = http_client_>PostJson(url, json_body);
    
    if (!http_resp.IsSuccess()) {
        return "";
    }
    
    SovereignSEGResponse resp = SovereignSEGResponse::FromJson(http_resp.body);
    
    if (!resp.success) {
        return "";
    }
    
    active_graphs_[resp.graph_id] = plan;
    return resp.graph_id;
}

bool SovereignBackendAdapter::ExecuteGraph(const std::string& graph_id) {
    if (!initialized_) return false;
    
    std::string url = BuildUrl("/api/seg/execute");
    std::string json_body = "{\"graph_id\":\"" + EscapeJsonString(graph_id) + "\"}";
    
    HttpResponse http_resp = http_client_>PostJson(url, json_body);
    
    return http_resp.IsSuccess();
}

std::string SovereignBackendAdapter::MakeDecision(const std::string& context,
                                                   const std::vector<std::string>& options) {
    if (!initialized_) return "";
    
    SovereignDecisionRequest req;
    req.context = context;
    req.options = options;
    
    std::string url = BuildUrl("/api/decision");
    std::string json_body = req.ToJson();
    
    HttpResponse http_resp = http_client_>PostJson(url, json_body);
    
    if (!http_resp.IsSuccess()) {
        return "";
    }
    
    SovereignDecisionResponse resp = SovereignDecisionResponse::FromJson(http_resp.body);
    
    if (!resp.success) {
        return "";
    }
    
    return resp.selected_option;
}

ResourceMetrics SovereignBackendAdapter::GetResourceUsage() {
    if (!initialized_) return ResourceMetrics{};
    
    std::string url = BuildUrl("/api/metrics");
    HttpResponse http_resp = http_client_>Get(url);
    
    if (!http_resp.IsSuccess()) {
        return ResourceMetrics{};
    }
    
    ResourceMetrics metrics;
    
    // Parse metrics from JSON
    auto GetDouble = [&](const std::string& key) -> double {
        size_t pos = http_resp.body.find("\"" + key + "\"");
        if (pos == std::string::npos) return 0.0;
        pos = http_resp.body.find(":", pos);
        if (pos == std::string::npos) return 0.0;
        pos = http_resp.body.find_first_of("0123456789-.", pos);
        if (pos == std::string::npos) return 0.0;
        size_t end = http_resp.body.find_first_of(",}", pos);
        if (end == std::string::npos) return 0.0;
        try {
            return std::stod(http_resp.body.substr(pos, end - pos));
        } catch (...) {
            return 0.0;
        }
    };
    
    metrics.cpu_percent = GetDouble("cpu_percent");
    metrics.memory_mb = GetDouble("memory_mb");
    metrics.gpu_percent = GetDouble("gpu_percent");
    metrics.gpu_memory_mb = GetDouble("gpu_memory_mb");
    
    return metrics;
}

bool SovereignBackendAdapter::HealthCheck() {
    if (!initialized_) return false;
    
    std::string url = BuildUrl("/api/health");
    HttpResponse http_resp = http_client_>Get(url);
    
    if (!http_resp.IsSuccess()) {
        return false;
    }
    
    SovereignHealthResponse resp = SovereignHealthResponse::FromJson(http_resp.body);
    return resp.healthy;
}

std::string SovereignBackendAdapter::GetVersion() {
    if (!initialized_) return "";
    
    std::string url = BuildUrl("/api/health");
    HttpResponse http_resp = http_client_>Get(url);
    
    if (!http_resp.IsSuccess()) {
        return "";
    }
    
    SovereignHealthResponse resp = SovereignHealthResponse::FromJson(http_resp.body);
    return resp.version;
}

bool SovereignBackendAdapter::WaitForReady(int timeout_seconds) {
    if (!initialized_) return false;
    
    auto start = Clock::now();
    auto timeout = std::chrono::seconds(timeout_seconds);
    
    while (Clock::now() - start < timeout) {
        if (HealthCheck()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    
    return false;
}

SovereignBackendAdapter::Stats SovereignBackendAdapter::GetStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void SovereignBackendAdapter::ResetStats() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = Stats{};
}

std::string SovereignBackendAdapter::BuildUrl(const std::string& path) {
    return endpoint_ + path;
}

bool SovereignBackendAdapter::ParseEndpoint(const std::string& endpoint, 
                                            std::string& host, int& port) {
    // Simple endpoint parsing
    if (endpoint.substr(0, 7) == "http://") {
        std::string rest = endpoint.substr(7);
        size_t colon = rest.find(':');
        if (colon != std::string::npos) {
            host = rest.substr(0, colon);
            try {
                port = std::stoi(rest.substr(colon + 1));
            } catch (...) {
                port = 8080;
            }
        } else {
            host = rest;
            port = 8080;
        }
        return true;
    }
    return false;
}

void SovereignBackendAdapter::UpdateStats(bool success, double latency_ms, int tokens) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    stats_.total_requests++;
    if (success) {
        stats_.successful_requests++;
    } else {
        stats_.failed_requests++;
    }
    
    // Running average
    if (stats_.total_requests == 1) {
        stats_.average_latency_ms = latency_ms;
    } else {
        stats_.average_latency_ms = 
            (stats_.average_latency_ms * (stats_.total_requests - 1) + latency_ms) 
            / stats_.total_requests;
    }
    
    stats_.total_tokens_generated += tokens;
    stats_.total_generation_time_ms += latency_ms;
}

// Factory function
std::unique_ptr<BackendAdapter> CreateSovereignBackendAdapter() {
    return std::make_unique<SovereignBackendAdapter>();
}

} // namespace rawrxd::benchmark
