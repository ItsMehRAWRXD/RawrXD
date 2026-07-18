// Ollama Backend Adapter Implementation
// Copyright (c) 2026 RawrXD Team

#include "ollama_backend.hpp"
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>

namespace rawrxd::benchmark {

// ============================================================================
// Ollama API Types Implementation
// ============================================================================

std::string OllamaGenerateRequest::Options::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"numa\":" << numa << ",";
    oss << "\"num_ctx\":" << num_ctx << ",";
    oss << "\"num_keep\":" << num_keep << ",";
    oss << "\"seed\":" << seed << ",";
    oss << "\"num_predict\":" << num_predict << ",";
    oss << "\"top_k\":" << top_k << ",";
    oss << "\"top_p\":" << top_p << ",";
    oss << "\"temperature\":" << temperature << ",";
    oss << "\"repeat_penalty\":" << repeat_penalty << ",";
    oss << "\"repeat_last_n\":" << repeat_last_n << ",";
    oss << "\"tfs_z\":" << tfs_z << ",";
    oss << "\"mirostat\":" << mirostat << ",";
    oss << "\"mirostat_eta\":" << mirostat_eta << ",";
    oss << "\"mirostat_tau\":" << mirostat_tau << ",";
    oss << "\"num_gpu\":" << num_gpu << ",";
    oss << "\"main_gpu\":" << main_gpu << ",";
    oss << "\"low_vram\":" << (low_vram ? "true" : "false") << ",";
    oss << "\"f16_kv\":" << (f16_kv ? "true" : "false") << ",";
    oss << "\"vocab_only\":" << vocab_only << ",";
    oss << "\"use_mmap\":" << use_mmap << ",";
    oss << "\"use_mlock\":" << use_mlock << ",";
    oss << "\"num_thread\":" << num_thread;
    oss << "}";
    return oss.str();
}

std::string OllamaGenerateRequest::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"model\":\"" << EscapeJsonString(model) << "\",";
    oss << "\"prompt\":\"" << EscapeJsonString(prompt) << "\",";
    
    if (!images.empty()) {
        oss << "\"images\":[";
        for (size_t i = 0; i < images.size(); ++i) {
            if (i > 0) oss << ",";
            oss << "\"" << EscapeJsonString(images[i]) << "\"";
        }
        oss << "],";
    }
    
    if (!format.empty()) {
        oss << "\"format\":\"" << EscapeJsonString(format) << "\",";
    }
    
    oss << "\"options\":" << options.ToJson() << ",";
    oss << "\"stream\":" << (stream ? "true" : "false");
    
    if (!raw.empty()) {
        oss << ",\"raw\":\"" << EscapeJsonString(raw) << "\"";
    }
    
    oss << "}";
    return oss.str();
}

OllamaGenerateResponse OllamaGenerateResponse::FromJson(const std::string& json) {
    OllamaGenerateResponse response;
    
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
    
    response.model = GetString("model");
    response.created_at = GetString("created_at");
    response.response = GetString("response");
    response.done = json.find("\"done\":true") != std::string::npos ||
                   json.find("\"done\": true") != std::string::npos;
    
    if (response.done) {
        response.done_data.total_duration = GetInt("total_duration");
        response.done_data.load_duration = GetInt("load_duration");
        response.done_data.prompt_eval_count = GetInt("prompt_eval_count");
        response.done_data.prompt_eval_duration = GetInt("prompt_eval_duration");
        response.done_data.eval_count = GetInt("eval_count");
        response.done_data.eval_duration = GetInt("eval_duration");
    }
    
    response.success = !response.model.empty();
    
    return response;
}

std::string OllamaChatMessage::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"role\":\"" << EscapeJsonString(role) << "\",";
    oss << "\"content\":\"" << EscapeJsonString(content) << "\"";
    
    if (!images.empty()) {
        oss << ",\"images\":[";
        for (size_t i = 0; i < images.size(); ++i) {
            if (i > 0) oss << ",";
            oss << "\"" << EscapeJsonString(images[i]) << "\"";
        }
        oss << "]";
    }
    
    oss << "}";
    return oss.str();
}

OllamaChatMessage OllamaChatMessage::FromJson(const std::string& json) {
    OllamaChatMessage msg;
    
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
    
    msg.role = GetString("role");
    msg.content = GetString("content");
    
    return msg;
}

std::string OllamaChatRequest::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"model\":\"" << EscapeJsonString(model) << "\",";
    oss << "\"messages\":[";
    for (size_t i = 0; i < messages.size(); ++i) {
        if (i > 0) oss << ",";
        oss << messages[i].ToJson();
    }
    oss << "],";
    oss << "\"options\":" << options.ToJson() << ",";
    
    if (!format.empty()) {
        oss << "\"format\":\"" << EscapeJsonString(format) << "\",";
    }
    
    oss << "\"stream\":" << (stream ? "true" : "false") << ",";
    oss << "\"keep_alive\":\"" << EscapeJsonString(keep_alive) << "\"";
    oss << "}";
    return oss.str();
}

OllamaChatResponse OllamaChatResponse::FromJson(const std::string& json) {
    OllamaChatResponse response;
    
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
    
    response.model = GetString("model");
    response.created_at = GetString("created_at");
    response.message = OllamaChatMessage::FromJson(json);
    response.done = json.find("\"done\":true") != std::string::npos ||
                   json.find("\"done\": true") != std::string::npos;
    
    if (response.done) {
        response.done_data.total_duration = GetInt("total_duration");
        response.done_data.load_duration = GetInt("load_duration");
        response.done_data.prompt_eval_count = GetInt("prompt_eval_count");
        response.done_data.prompt_eval_duration = GetInt("prompt_eval_duration");
        response.done_data.eval_count = GetInt("eval_count");
        response.done_data.eval_duration = GetInt("eval_duration");
    }
    
    response.success = !response.model.empty();
    
    return response;
}

OllamaListResponse OllamaListResponse::FromJson(const std::string& json) {
    OllamaListResponse response;
    
    // Parse models array
    size_t models_pos = json.find("\"models\"");
    if (models_pos == std::string::npos) {
        response.success = false;
        return response;
    }
    
    size_t arr_start = json.find("[", models_pos);
    size_t arr_end = json.find("]", arr_start);
    if (arr_start == std::string::npos || arr_end == std::string::npos) {
        response.success = false;
        return response;
    }
    
    std::string arr_content = json.substr(arr_start + 1, arr_end - arr_start - 1);
    
    // Simple parsing - split by object boundaries
    size_t pos = 0;
    while (pos < arr_content.length()) {
        size_t obj_start = arr_content.find("{", pos);
        if (obj_start == std::string::npos) break;
        
        size_t obj_end = arr_content.find("}", obj_start);
        if (obj_end == std::string::npos) break;
        
        std::string obj = arr_content.substr(obj_start, obj_end - obj_start + 1);
        
        OllamaModelInfo info;
        
        auto GetString = [&](const std::string& key) -> std::string {
            size_t p = obj.find("\"" + key + "\"");
            if (p == std::string::npos) return "";
            p = obj.find(":", p);
            if (p == std::string::npos) return "";
            p = obj.find_first_of("\"", p);
            if (p == std::string::npos) return "";
            size_t e = obj.find_first_of("\"", p + 1);
            if (e == std::string::npos) return "";
            return obj.substr(p + 1, e - p - 1);
        };
        
        auto GetInt64 = [&](const std::string& key) -> int64_t {
            size_t p = obj.find("\"" + key + "\"");
            if (p == std::string::npos) return 0;
            p = obj.find(":", p);
            if (p == std::string::npos) return 0;
            p = obj.find_first_of("0123456789-", p);
            if (p == std::string::npos) return 0;
            size_t e = obj.find_first_of(",}", p);
            if (e == std::string::npos) return 0;
            try {
                return std::stoll(obj.substr(p, e - p));
            } catch (...) {
                return 0;
            }
        };
        
        info.name = GetString("name");
        info.modified_at = GetString("modified_at");
        info.size = GetInt64("size");
        info.digest = GetString("digest");
        info.details.format = GetString("format");
        info.details.family = GetString("family");
        info.details.parameter_size = GetString("parameter_size");
        info.details.quantization_level = GetString("quantization_level");
        
        response.models.push_back(info);
        pos = obj_end + 1;
    }
    
    response.success = true;
    return response;
}

OllamaPullResponse OllamaPullResponse::FromJson(const std::string& json) {
    OllamaPullResponse response;
    
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
    
    response.status = GetString("status");
    response.digest = GetString("digest");
    response.total = GetInt("total");
    response.completed = GetInt("completed");
    response.success = !response.status.empty();
    
    return response;
}

OllamaEmbedResponse OllamaEmbedResponse::FromJson(const std::string& json) {
    OllamaEmbedResponse response;
    
    // Parse embedding array
    size_t embed_pos = json.find("\"embedding\"");
    if (embed_pos == std::string::npos) {
        response.success = false;
        return response;
    }
    
    size_t arr_start = json.find("[", embed_pos);
    size_t arr_end = json.find("]", arr_start);
    if (arr_start == std::string::npos || arr_end == std::string::npos) {
        response.success = false;
        return response;
    }
    
    std::string arr_content = json.substr(arr_start + 1, arr_end - arr_start - 1);
    
    std::istringstream iss(arr_content);
    std::string token;
    while (std::getline(iss, token, ',')) {
        try {
            response.embedding.push_back(std::stod(token));
        } catch (...) {
            // Skip invalid values
        }
    }
    
    response.success = !response.embedding.empty();
    return response;
}

OllamaPsResponse OllamaPsResponse::FromJson(const std::string& json) {
    OllamaPsResponse response;
    
    // Parse models array
    size_t models_pos = json.find("\"models\"");
    if (models_pos == std::string::npos) {
        response.success = false;
        return response;
    }
    
    size_t arr_start = json.find("[", models_pos);
    size_t arr_end = json.find("]", arr_start);
    if (arr_start == std::string::npos || arr_end == std::string::npos) {
        response.success = false;
        return response;
    }
    
    std::string arr_content = json.substr(arr_start + 1, arr_end - arr_start - 1);
    
    // Simple parsing
    size_t pos = 0;
    while (pos < arr_content.length()) {
        size_t obj_start = arr_content.find("{", pos);
        if (obj_start == std::string::npos) break;
        
        size_t obj_end = arr_content.find("}", obj_start);
        if (obj_end == std::string::npos) break;
        
        std::string obj = arr_content.substr(obj_start, obj_end - obj_start + 1);
        
        OllamaPsResponse::RunningModel model;
        
        auto GetString = [&](const std::string& key) -> std::string {
            size_t p = obj.find("\"" + key + "\"");
            if (p == std::string::npos) return "";
            p = obj.find(":", p);
            if (p == std::string::npos) return "";
            p = obj.find_first_of("\"", p);
            if (p == std::string::npos) return "";
            size_t e = obj.find_first_of("\"", p + 1);
            if (e == std::string::npos) return "";
            return obj.substr(p + 1, e - p - 1);
        };
        
        auto GetInt64 = [&](const std::string& key) -> int64_t {
            size_t p = obj.find("\"" + key + "\"");
            if (p == std::string::npos) return 0;
            p = obj.find(":", p);
            if (p == std::string::npos) return 0;
            p = obj.find_first_of("0123456789-", p);
            if (p == std::string::npos) return 0;
            size_t e = obj.find_first_of(",}", p);
            if (e == std::string::npos) return 0;
            try {
                return std::stoll(obj.substr(p, e - p));
            } catch (...) {
                return 0;
            }
        };
        
        model.name = GetString("name");
        model.model = GetString("model");
        model.size = GetInt64("size");
        model.digest = GetString("digest");
        model.expires_at = GetInt64("expires_at");
        model.size_vram = GetInt64("size_vram");
        
        response.models.push_back(model);
        pos = obj_end + 1;
    }
    
    response.success = true;
    return response;
}

// ============================================================================
// Ollama Backend Adapter Implementation
// ============================================================================

OllamaBackendAdapter::OllamaBackendAdapter() = default;
OllamaBackendAdapter::~OllamaBackendAdapter() {
    Shutdown();
}

bool OllamaBackendAdapter::Initialize(const BenchmarkConfig& config) {
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
    http_client_>SetDefaultTimeout(5000, 30000, 60000);
    http_client_>SetRetryPolicy(3, 1000, true);
    http_client_>EnableConnectionPool(10);
    
    initialized_ = true;
    return true;
}

void OllamaBackendAdapter::Shutdown() {
    if (!initialized_) return;
    
    http_client_>Shutdown();
    http_client_.reset();
    
    initialized_ = false;
}

std::string OllamaBackendAdapter::Generate(const std::string& prompt, int max_tokens) {
    if (!initialized_) {
        return "";
    }
    
    OllamaGenerateRequest req;
    req.model = model_name_;
    req.prompt = prompt;
    req.options.seed = default_seed_;
    req.options.temperature = default_temperature_;
    req.options.num_predict = max_tokens > 0 ? max_tokens : default_max_tokens_;
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
    
    OllamaGenerateResponse resp = OllamaGenerateResponse::FromJson(http_resp.body);
    
    if (!resp.success) {
        UpdateStats(false, latency_ms);
        return "";
    }
    
    last_latency_ms_ = latency_ms;
    last_tokens_per_sec_ = resp.GetTokensPerSecond();
    
    UpdateStats(true, latency_ms, resp.done_data.eval_count);
    
    return resp.response;
}

std::string OllamaBackendAdapter::SpawnAgent(const std::string& role, 
                                             const std::string& context) {
    // Ollama doesn't have native agent support, simulate with a prompt
    std::string agent_id = "ollama_agent_" + std::to_string(next_agent_id_++);
    
    std::string prompt = SimulateAgentPrompt(role, context, "Initialize");
    std::string response = Generate(prompt, 256);
    
    if (!response.empty()) {
        simulated_agents_[agent_id] = {role, context};
        return agent_id;
    }
    
    return "";
}

bool OllamaBackendAdapter::DestroyAgent(const std::string& agent_id) {
    auto it = simulated_agents_.find(agent_id);
    if (it != simulated_agents_.end()) {
        simulated_agents_.erase(it);
        return true;
    }
    return false;
}

std::vector<std::string> OllamaBackendAdapter::ListAgents() {
    std::vector<std::string> agents;
    for (const auto& [id, _] : simulated_agents_) {
        agents.push_back(id);
    }
    return agents;
}

std::vector<std::string> OllamaBackendAdapter::SpawnSwarm(int count, 
                                                           const std::string& task) {
    std::vector<std::string> agents;
    
    for (int i = 0; i < count; ++i) {
        std::string agent_id = SpawnAgent("swarm_member", task);
        if (!agent_id.empty()) {
            agents.push_back(agent_id);
        }
    }
    
    return agents;
}

std::vector<std::string> OllamaBackendAdapter::ExecuteSwarm(
    const std::vector<std::string>& agents, const std::string& task) {
    
    std::vector<std::string> results;
    
    for (const auto& agent_id : agents) {
        auto it = simulated_agents_.find(agent_id);
        if (it != simulated_agents_.end()) {
            std::string prompt = SimulateAgentPrompt(it->second.first, it->second.second, task);
            std::string result = Generate(prompt, 256);
            results.push_back(result);
        }
    }
    
    return results;
}

std::string OllamaBackendAdapter::CreateExecutionGraph(const std::string& plan) {
    // Ollama doesn't support SEG - return empty
    return "";
}

bool OllamaBackendAdapter::ExecuteGraph(const std::string& graph_id) {
    // Ollama doesn't support SEG - return false
    return false;
}

std::string OllamaBackendAdapter::MakeDecision(const std::string& context,
                                                const std::vector<std::string>& options) {
    if (!initialized_) return "";
    
    // Use chat API for decision making
    OllamaChatRequest req;
    req.model = model_name_;
    
    OllamaChatMessage system_msg;
    system_msg.role = "system";
    system_msg.content = "You are a decision-making assistant. Select the best option from the given choices.";
    req.messages.push_back(system_msg);
    
    OllamaChatMessage user_msg;
    user_msg.role = "user";
    user_msg.content = SimulateDecisionPrompt(context, options);
    req.messages.push_back(user_msg);
    
    req.options.seed = default_seed_;
    req.options.temperature = 0.0f;
    req.options.num_predict = 64;
    req.stream = false;
    
    std::string url = BuildUrl("/api/chat");
    std::string json_body = req.ToJson();
    
    HttpResponse http_resp = http_client_>PostJson(url, json_body);
    
    if (!http_resp.IsSuccess()) {
        return "";
    }
    
    OllamaChatResponse resp = OllamaChatResponse::FromJson(http_resp.body);
    
    if (!resp.success) {
        return "";
    }
    
    // Parse the response to extract the selected option
    std::string decision = resp.message.content;
    
    // Try to match against options
    for (const auto& opt : options) {
        if (decision.find(opt) != std::string::npos) {
            return opt;
        }
    }
    
    // Return first option if no match found
    return options.empty() ? "" : options[0];
}

ResourceMetrics OllamaBackendAdapter::GetResourceUsage() {
    if (!initialized_) return ResourceMetrics{};
    
    // Ollama doesn't expose detailed resource metrics via API
    // Return empty metrics
    return ResourceMetrics{};
}

bool OllamaBackendAdapter::HealthCheck() {
    if (!initialized_) return false;
    
    std::string url = BuildUrl("/api/tags");
    HttpResponse http_resp = http_client_>Get(url);
    
    return http_resp.IsSuccess();
}

std::vector<OllamaModelInfo> OllamaBackendAdapter::ListModels() {
    std::vector<OllamaModelInfo> models;
    
    if (!initialized_) return models;
    
    std::string url = BuildUrl("/api/tags");
    HttpResponse http_resp = http_client_>Get(url);
    
    if (!http_resp.IsSuccess()) {
        return models;
    }
    
    OllamaListResponse resp = OllamaListResponse::FromJson(http_resp.body);
    
    if (resp.success) {
        models = resp.models;
    }
    
    return models;
}

bool OllamaBackendAdapter::PullModel(const std::string& model_name) {
    if (!initialized_) return false;
    
    std::string url = BuildUrl("/api/pull");
    std::string json_body = "{\"name\":\"" + EscapeJsonString(model_name) + "\",\"stream\":false}";
    
    HttpResponse http_resp = http_client_>PostJson(url, json_body);
    
    return http_resp.IsSuccess();
}

bool OllamaBackendAdapter::DeleteModel(const std::string& model_name) {
    if (!initialized_) return false;
    
    std::string url = BuildUrl("/api/delete");
    std::string json_body = "{\"name\":\"" + EscapeJsonString(model_name) + "\"}";
    
    HttpResponse http_resp = http_client_>PostJson(url, json_body);
    
    return http_resp.IsSuccess();
}

bool OllamaBackendAdapter::IsModelRunning(const std::string& model_name) {
    if (!initialized_) return false;
    
    std::string url = BuildUrl("/api/ps");
    HttpResponse http_resp = http_client_>Get(url);
    
    if (!http_resp.IsSuccess()) {
        return false;
    }
    
    OllamaPsResponse resp = OllamaPsResponse::FromJson(http_resp.body);
    
    if (!resp.success) {
        return false;
    }
    
    for (const auto& model : resp.models) {
        if (model.name == model_name || model.model == model_name) {
            return true;
        }
    }
    
    return false;
}

bool OllamaBackendAdapter::WaitForModelReady(const std::string& model_name, 
                                              int timeout_seconds) {
    if (!initialized_) return false;
    
    auto start = Clock::now();
    auto timeout = std::chrono::seconds(timeout_seconds);
    
    while (Clock::now() - start < timeout) {
        if (IsModelRunning(model_name)) {
            return true;
        }
        
        // Try to load the model
        std::string url = BuildUrl("/api/generate");
        std::string json_body = "{\"model\":\"" + EscapeJsonString(model_name) + 
                               "\",\"prompt\":\"\",\"stream\":false}";
        http_client_>PostJson(url, json_body);
        
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    
    return false;
}

OllamaBackendAdapter::Stats OllamaBackendAdapter::GetStats() const {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    return stats_;
}

void OllamaBackendAdapter::ResetStats() {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    stats_ = Stats{};
}

std::string OllamaBackendAdapter::BuildUrl(const std::string& path) {
    return endpoint_ + path;
}

bool OllamaBackendAdapter::ParseEndpoint(const std::string& endpoint, 
                                          std::string& host, int& port) {
    if (endpoint.substr(0, 7) == "http://") {
        std::string rest = endpoint.substr(7);
        size_t colon = rest.find(':');
        if (colon != std::string::npos) {
            host = rest.substr(0, colon);
            try {
                port = std::stoi(rest.substr(colon + 1));
            } catch (...) {
                port = 11434;
            }
        } else {
            host = rest;
            port = 11434;
        }
        return true;
    }
    return false;
}

void OllamaBackendAdapter::UpdateStats(bool success, double latency_ms, int tokens) {
    std::lock_guard<std::mutex> lock(stats_mutex_);
    
    stats_.total_requests++;
    if (success) {
        stats_.successful_requests++;
    } else {
        stats_.failed_requests++;
    }
    
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

std::string OllamaBackendAdapter::SimulateAgentPrompt(const std::string& role,
                                                       const std::string& context,
                                                       const std::string& task) {
    return "You are a " + role + " agent. Context: " + context + 
           "\nTask: " + task + "\nRespond concisely.";
}

std::string OllamaBackendAdapter::SimulateDecisionPrompt(
    const std::string& context, const std::vector<std::string>& options) {
    
    std::string prompt = "Context: " + context + "\n\nOptions:\n";
    for (size_t i = 0; i < options.size(); ++i) {
        prompt += std::to_string(i + 1) + ". " + options[i] + "\n";
    }
    prompt += "\nSelect the best option by number or name.";
    return prompt;
}

// Factory function
std::unique_ptr<BackendAdapter> CreateOllamaBackendAdapter() {
    return std::make_unique<OllamaBackendAdapter>();
}

} // namespace rawrxd::benchmark
