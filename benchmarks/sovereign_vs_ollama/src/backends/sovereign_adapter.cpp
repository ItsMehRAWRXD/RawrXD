// sovereign_adapter.cpp
// HTTP adapter for RawrXD Sovereign Runtime (localhost:8080)

#include "backends/sovereign_adapter.hpp"
#include <curl/curl.h>
#include <sstream>
#include <iostream>
#include <cstring>

namespace Benchmark {
namespace Backends {

// CURL write callback
static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

SovereignAdapter::SovereignAdapter(const std::string& base_url)
    : base_url_(base_url), curl_(nullptr) {
    curl_ = curl_easy_init();
    if (!curl_) {
        throw std::runtime_error("Failed to initialize CURL");
    }
}

SovereignAdapter::~SovereignAdapter() {
    if (curl_) {
        curl_easy_cleanup(curl_);
    }
}

bool SovereignAdapter::IsAvailable() {
    std::string response;
    return HttpGet("/health", response);
}

std::string SovereignAdapter::GetBackendName() const {
    return "Sovereign";
}

std::string SovereignAdapter::GetBackendVersion() {
    std::string response;
    if (HttpGet("/version", response)) {
        return ParseVersion(response);
    }
    return "unknown";
}

InferenceResult SovereignAdapter::RunInference(const InferenceRequest& request) {
    InferenceResult result;
    result.success = false;
    
    // Build JSON request
    std::stringstream json;
    json << "{";
    json << "\"model\":\"" << request.model << "\",";
    json << "\"prompt\":\"" << EscapeJson(request.prompt) << "\",";
    json << "\"temperature\":" << request.temperature << ",";
    json << "\"max_tokens\":" << request.max_tokens;
    if (request.seed.has_value()) {
        json << ",\"seed\":" << request.seed.value();
    }
    json << "}";
    
    std::string response;
    auto start = std::chrono::high_resolution_clock::now();
    
    bool http_success = HttpPost("/v1/completions", json.str(), response);
    
    auto end = std::chrono::high_resolution_clock::now();
    result.total_latency_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    if (!http_success) {
        result.error_message = "HTTP request failed";
        return result;
    }
    
    // Parse response
    result = ParseInferenceResponse(response);
    result.total_latency_ms = result.total_latency_ms > 0 ? result.total_latency_ms : 
                              std::chrono::duration<double, std::milli>(end - start).count();
    
    return result;
}

AgentSpawnResult SovereignAdapter::SpawnAgent(const AgentSpawnRequest& request) {
    AgentSpawnResult result;
    result.success = false;
    
    std::stringstream json;
    json << "{";
    json << "\"agent_type\":\"" << request.agent_type << "\",";
    json << "\"task_description\":\"" << EscapeJson(request.task_description) << "\",";
    json << "\"swarm_size\":" << request.swarm_size;
    json << "}";
    
    std::string response;
    auto start = std::chrono::high_resolution_clock::now();
    
    bool http_success = HttpPost("/v1/agents/spawn", json.str(), response);
    
    auto end = std::chrono::high_resolution_clock::now();
    result.spawn_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    if (!http_success) {
        result.error_message = "HTTP request failed";
        return result;
    }
    
    // Parse response
    result = ParseAgentSpawnResponse(response);
    result.spawn_time_ms = result.spawn_time_ms > 0 ? result.spawn_time_ms :
                           std::chrono::duration<double, std::milli>(end - start).count();
    
    return result;
}

SwarmResult SovereignAdapter::ExecuteSwarm(const SwarmRequest& request) {
    SwarmResult result;
    result.success = false;
    
    std::stringstream json;
    json << "{";
    json << "\"task\":\"" << EscapeJson(request.task) << "\",";
    json << "\"agent_count\":" << request.agent_count << ",";
    json << "\"coordination_strategy\":\"" << request.coordination_strategy << "\"";
    json << "}";
    
    std::string response;
    auto start = std::chrono::high_resolution_clock::now();
    
    bool http_success = HttpPost("/v1/swarm/execute", json.str(), response);
    
    auto end = std::chrono::high_resolution_clock::now();
    result.total_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    if (!http_success) {
        result.error_message = "HTTP request failed";
        return result;
    }
    
    result = ParseSwarmResponse(response);
    result.total_time_ms = result.total_time_ms > 0 ? result.total_time_ms :
                           std::chrono::duration<double, std::milli>(end - start).count();
    
    return result;
}

bool SovereignAdapter::HttpGet(const std::string& endpoint, std::string& response) {
    std::string url = base_url_ + endpoint;
    
    curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl_, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl_, CURLOPT_CONNECTTIMEOUT, 5L);
    
    CURLcode res = curl_easy_perform(curl_);
    
    if (res != CURLE_OK) {
        std::cerr << "CURL error: " << curl_easy_strerror(res) << std::endl;
        return false;
    }
    
    long http_code;
    curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &http_code);
    
    return http_code == 200;
}

bool SovereignAdapter::HttpPost(const std::string& endpoint, 
                                 const std::string& json_body, 
                                 std::string& response) {
    std::string url = base_url_ + endpoint;
    
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    
    curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, json_body.c_str());
    curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl_, CURLOPT_TIMEOUT, 300L);  // 5 min for inference
    curl_easy_setopt(curl_, CURLOPT_CONNECTTIMEOUT, 5L);
    
    CURLcode res = curl_easy_perform(curl_);
    
    curl_slist_free_all(headers);
    
    if (res != CURLE_OK) {
        std::cerr << "CURL error: " << curl_easy_strerror(res) << std::endl;
        return false;
    }
    
    long http_code;
    curl_easy_getinfo(curl_, CURLINFO_RESPONSE_CODE, &http_code);
    
    return http_code == 200;
}

InferenceResult SovereignAdapter::ParseInferenceResponse(const std::string& json) {
    InferenceResult result;
    result.success = true;
    
    // Simple JSON parsing (in production, use a proper JSON library)
    size_t tokens_pos = json.find("\"tokens_generated\":");
    if (tokens_pos != std::string::npos) {
        result.tokens_generated = std::stoi(json.substr(tokens_pos + 19));
    }
    
    size_t ttft_pos = json.find("\"time_to_first_token_ms\":");
    if (ttft_pos != std::string::npos) {
        result.time_to_first_token_ms = std::stod(json.substr(ttft_pos + 25));
    }
    
    size_t tps_pos = json.find("\"tokens_per_second\":");
    if (tps_pos != std::string::npos) {
        result.tokens_per_second = std::stod(json.substr(tps_pos + 20));
    }
    
    size_t text_pos = json.find("\"text\":\"");
    if (text_pos != std::string::npos) {
        size_t end_pos = json.find("\"", text_pos + 8);
        if (end_pos != std::string::npos) {
            result.generated_text = json.substr(text_pos + 8, end_pos - text_pos - 8);
        }
    }
    
    return result;
}

AgentSpawnResult SovereignAdapter::ParseAgentSpawnResponse(const std::string& json) {
    AgentSpawnResult result;
    result.success = true;
    
    size_t id_pos = json.find("\"agent_id\":\"");
    if (id_pos != std::string::npos) {
        size_t end_pos = json.find("\"", id_pos + 12);
        if (end_pos != std::string::npos) {
            result.agent_id = json.substr(id_pos + 12, end_pos - id_pos - 12);
        }
    }
    
    size_t mem_pos = json.find("\"memory_mb\":");
    if (mem_pos != std::string::npos) {
        result.memory_mb = std::stod(json.substr(mem_pos + 12));
    }
    
    return result;
}

SwarmResult SovereignAdapter::ParseSwarmResponse(const std::string& json) {
    SwarmResult result;
    result.success = true;
    
    size_t completed_pos = json.find("\"tasks_completed\":");
    if (completed_pos != std::string::npos) {
        result.tasks_completed = std::stoi(json.substr(completed_pos + 18));
    }
    
    size_t efficiency_pos = json.find("\"efficiency\":");
    if (efficiency_pos != std::string::npos) {
        result.efficiency = std::stod(json.substr(efficiency_pos + 13));
    }
    
    return result;
}

std::string SovereignAdapter::ParseVersion(const std::string& json) {
    size_t ver_pos = json.find("\"version\":\"");
    if (ver_pos != std::string::npos) {
        size_t end_pos = json.find("\"", ver_pos + 11);
        if (end_pos != std::string::npos) {
            return json.substr(ver_pos + 11, end_pos - ver_pos - 11);
        }
    }
    return "unknown";
}

std::string SovereignAdapter::EscapeJson(const std::string& input) {
    std::string output;
    output.reserve(input.size());
    
    for (char c : input) {
        switch (c) {
            case '"': output += "\\\""; break;
            case '\\': output += "\\\\"; break;
            case '\b': output += "\\b"; break;
            case '\f': output += "\\f"; break;
            case '\n': output += "\\n"; break;
            case '\r': output += "\\r"; break;
            case '\t': output += "\\t"; break;
            default: output += c; break;
        }
    }
    
    return output;
}

} // namespace Backends
} // namespace Benchmark
