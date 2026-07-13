// Sovereign Backend Adapter
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "benchmark_common.hpp"
#include <curl/curl.h>
#include <json/json.h>
#include <thread>
#include <future>

namespace rawrxd::benchmark {

// ============================================================================
// Sovereign Backend Adapter
// ============================================================================
class SovereignAdapter : public BackendAdapter {
public:
    SovereignAdapter() = default;
    ~SovereignAdapter() override { Shutdown(); }
    
    bool Initialize(const BenchmarkConfig& config) override {
        config_ = config;
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl_ = curl_easy_init();
        if (!curl_) {
            std::cerr << "Failed to initialize CURL\n";
            return false;
        }
        
        // Test connection to Sovereign endpoint
        if (!TestConnection()) {
            std::cerr << "Failed to connect to Sovereign endpoint: " << config.sovereign_endpoint << "\n";
            return false;
        }
        
        std::cout << "Sovereign adapter initialized: " << config.sovereign_endpoint << "\n";
        return true;
    }
    
    void Shutdown() override {
        if (curl_) {
            curl_easy_cleanup(curl_);
            curl_ = nullptr;
        }
        curl_global_cleanup();
    }
    
    std::string Generate(const std::string& prompt, int max_tokens) override {
        Timer timer;
        timer.Start();
        
        Json::Value request;
        request["prompt"] = prompt;
        request["max_tokens"] = max_tokens;
        request["temperature"] = config_.temperature;
        request["stream"] = false;
        
        // Add Sovereign-specific options
        if (config_.enable_seg) {
            request["use_seg"] = true;
        }
        if (config_.enable_learning) {
            request["enable_learning"] = true;
        }
        
        auto response = HttpPost("/v1/generate", request);
        
        timer.Stop();
        last_latency_ms_ = timer.ElapsedMs();
        
        // Parse response for token count
        Json::Reader reader;
        Json::Value root;
        if (reader.parse(response, root)) {
            int tokens_generated = root.get("tokens_generated", 0).asInt();
            if (tokens_generated > 0) {
                last_tokens_per_sec_ = tokens_generated / (last_latency_ms_ / 1000.0);
            }
        }
        
        return response;
    }
    
    double GetLastLatencyMs() const override { return last_latency_ms_; }
    double GetLastTokensPerSec() const override { return last_tokens_per_sec_; }
    
    std::string SpawnAgent(const std::string& role, const std::string& context) override {
        Json::Value request;
        request["role"] = role;
        request["context"] = context;
        request["backend"] = "sovereign";
        
        auto response = HttpPost("/v1/agents/spawn", request);
        
        // Extract agent ID from response
        Json::Reader reader;
        Json::Value root;
        if (reader.parse(response, root)) {
            return root.get("agent_id", "").asString();
        }
        return "";
    }
    
    bool DestroyAgent(const std::string& agent_id) override {
        Json::Value request;
        request["agent_id"] = agent_id;
        
        auto response = HttpPost("/v1/agents/destroy", request);
        return response.find("\"success\":true") != std::string::npos;
    }
    
    std::vector<std::string> ListAgents() override {
        auto response = HttpGet("/v1/agents/list");
        
        std::vector<std::string> agents;
        Json::Reader reader;
        Json::Value root;
        if (reader.parse(response, root) && root.isMember("agents")) {
            const auto& arr = root["agents"];
            for (const auto& agent : arr) {
                agents.push_back(agent.asString());
            }
        }
        return agents;
    }
    
    std::vector<std::string> SpawnSwarm(int count, const std::string& task) override {
        Json::Value request;
        request["count"] = count;
        request["task"] = task;
        request["backend"] = "sovereign";
        
        auto response = HttpPost("/v1/swarm/spawn", request);
        
        std::vector<std::string> agents;
        Json::Reader reader;
        Json::Value root;
        if (reader.parse(response, root) && root.isMember("agent_ids")) {
            const auto& arr = root["agent_ids"];
            for (const auto& id : arr) {
                agents.push_back(id.asString());
            }
        }
        return agents;
    }
    
    std::vector<std::string> ExecuteSwarm(const std::vector<std::string>& agents,
                                           const std::string& task) override {
        Json::Value request;
        request["task"] = task;
        
        Json::Value agent_array(Json::arrayValue);
        for (const auto& id : agents) {
            agent_array.append(id);
        }
        request["agent_ids"] = agent_array;
        
        auto response = HttpPost("/v1/swarm/execute", request);
        
        std::vector<std::string> results;
        Json::Reader reader;
        Json::Value root;
        if (reader.parse(response, root) && root.isMember("results")) {
            const auto& arr = root["results"];
            for (const auto& r : arr) {
                results.push_back(r.asString());
            }
        }
        return results;
    }
    
    bool SupportsSEG() const override { return true; }
    
    std::string CreateExecutionGraph(const std::string& plan) override {
        Json::Value request;
        request["plan"] = plan;
        
        auto response = HttpPost("/v1/seg/create", request);
        
        Json::Reader reader;
        Json::Value root;
        if (reader.parse(response, root)) {
            return root.get("graph_id", "").asString();
        }
        return "";
    }
    
    bool ExecuteGraph(const std::string& graph_id) override {
        Json::Value request;
        request["graph_id"] = graph_id;
        
        auto response = HttpPost("/v1/seg/execute", request);
        return response.find("\"success\":true") != std::string::npos;
    }
    
    std::string MakeDecision(const std::string& context,
                            const std::vector<std::string>& options) override {
        Json::Value request;
        request["context"] = context;
        
        Json::Value opts(Json::arrayValue);
        for (const auto& opt : options) {
            opts.append(opt);
        }
        request["options"] = opts;
        
        auto response = HttpPost("/v1/decide", request);
        
        Json::Reader reader;
        Json::Value root;
        if (reader.parse(response, root)) {
            return root.get("decision", "").asString();
        }
        return "";
    }
    
    ResourceMetrics GetResourceUsage() override {
        auto response = HttpGet("/v1/metrics/resources");
        
        ResourceMetrics metrics;
        Json::Reader reader;
        Json::Value root;
        if (reader.parse(response, root)) {
            metrics.cpu_percent = root.get("cpu_percent", 0.0).asDouble();
            metrics.memory_mb = root.get("memory_mb", 0.0).asDouble();
            metrics.vram_mb = root.get("vram_mb", 0.0).asDouble();
            metrics.gpu_percent = root.get("gpu_percent", 0.0).asDouble();
        }
        return metrics;
    }
    
private:
    CURL* curl_ = nullptr;
    BenchmarkConfig config_;
    double last_latency_ms_ = 0.0;
    double last_tokens_per_sec_ = 0.0;
    
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
        userp->append(static_cast<char*>(contents), size * nmemb);
        return size * nmemb;
    }
    
    bool TestConnection() {
        auto response = HttpGet("/v1/health");
        return !response.empty() && response.find("\"status\":\"ok\"") != std::string::npos;
    }
    
    std::string HttpGet(const std::string& endpoint) {
        std::string url = config_.sovereign_endpoint + endpoint;
        std::string response;
        
        curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl_, CURLOPT_TIMEOUT, 30L);
        
        CURLcode res = curl_easy_perform(curl_);
        curl_easy_reset(curl_);
        
        if (res != CURLE_OK) {
            std::cerr << "HTTP GET failed: " << curl_easy_strerror(res) << "\n";
            return "";
        }
        
        return response;
    }
    
    std::string HttpPost(const std::string& endpoint, const Json::Value& json) {
        std::string url = config_.sovereign_endpoint + endpoint;
        std::string response;
        std::string post_data = json.toStyledString();
        
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        
        curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, post_data.c_str());
        curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl_, CURLOPT_TIMEOUT, 120L);
        
        CURLcode res = curl_easy_perform(curl_);
        curl_easy_reset(curl_);
        curl_slist_free_all(headers);
        
        if (res != CURLE_OK) {
            std::cerr << "HTTP POST failed: " << curl_easy_strerror(res) << "\n";
            return "";
        }
        
        return response;
    }
};

} // namespace rawrxd::benchmark
