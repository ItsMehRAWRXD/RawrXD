// Ollama Backend Adapter
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "benchmark_common.hpp"
#include <curl/curl.h>
#include <json/json.h>

namespace rawrxd::benchmark {

// ============================================================================
// Ollama Backend Adapter
// ============================================================================
class OllamaAdapter : public BackendAdapter {
public:
    OllamaAdapter() = default;
    ~OllamaAdapter() override { Shutdown(); }
    
    bool Initialize(const BenchmarkConfig& config) override {
        config_ = config;
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl_ = curl_easy_init();
        if (!curl_) {
            std::cerr << "Failed to initialize CURL\n";
            return false;
        }
        
        // Test connection to Ollama
        if (!TestConnection()) {
            std::cerr << "Failed to connect to Ollama: " << config.ollama_url << "\n";
            return false;
        }
        
        // Ensure model is available
        if (!PullModelIfNeeded()) {
            std::cerr << "Failed to ensure model availability: " << config.ollama_model << "\n";
            return false;
        }
        
        std::cout << "Ollama adapter initialized: " << config.ollama_url << " (model: " << config.ollama_model << ")\n";
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
        request["model"] = config_.ollama_model;
        request["prompt"] = prompt;
        request["stream"] = false;
        
        Json::Value options;
        options["num_predict"] = max_tokens;
        options["temperature"] = config_.temperature;
        request["options"] = options;
        
        auto response = HttpPost("/api/generate", request);
        
        timer.Stop();
        last_latency_ms_ = timer.ElapsedMs();
        
        // Parse response for token count
        Json::Reader reader;
        Json::Value root;
        if (reader.parse(response, root)) {
            int eval_count = root.get("eval_count", 0).asInt();
            if (eval_count > 0) {
                last_tokens_per_sec_ = eval_count / (last_latency_ms_ / 1000.0);
            }
        }
        
        return response;
    }
    
    double GetLastLatencyMs() const override { return last_latency_ms_; }
    double GetLastTokensPerSec() const override { return last_tokens_per_sec_; }
    
    // Ollama doesn't have native agent support, so we simulate it
    std::string SpawnAgent(const std::string& role, const std::string& context) override {
        // Ollama doesn't have persistent agents - we just return a simulated ID
        static int agent_counter = 0;
        return "ollama_agent_" + std::to_string(++agent_counter);
    }
    
    bool DestroyAgent(const std::string& agent_id) override {
        // No-op for Ollama
        return true;
    }
    
    std::vector<std::string> ListAgents() override {
        // Ollama doesn't track agents
        return {};
    }
    
    std::vector<std::string> SpawnSwarm(int count, const std::string& task) override {
        // Simulate swarm by generating multiple agent IDs
        std::vector<std::string> agents;
        for (int i = 0; i < count; ++i) {
            agents.push_back(SpawnAgent("worker", ""));
        }
        return agents;
    }
    
    std::vector<std::string> ExecuteSwarm(const std::vector<std::string>& agents,
                                           const std::string& task) override {
        // Execute task for each "agent" sequentially (Ollama limitation)
        std::vector<std::string> results;
        for (size_t i = 0; i < agents.size(); ++i) {
            auto response = Generate(task, config_.max_tokens);
            
            Json::Reader reader;
            Json::Value root;
            if (reader.parse(response, root)) {
                results.push_back(root.get("response", "").asString());
            } else {
                results.push_back("");
            }
        }
        return results;
    }
    
    bool SupportsSEG() const override { return false; }
    
    std::string CreateExecutionGraph(const std::string& plan) override {
        // Not supported - return empty
        return "";
    }
    
    bool ExecuteGraph(const std::string& graph_id) override {
        // Not supported
        return false;
    }
    
    std::string MakeDecision(const std::string& context,
                            const std::vector<std::string>& options) override {
        // Use LLM to make decision
        std::string prompt = "Given this context:\n" + context + "\n\n";
        prompt += "Choose the best option from:\n";
        for (size_t i = 0; i < options.size(); ++i) {
            prompt += std::to_string(i + 1) + ". " + options[i] + "\n";
        }
        prompt += "\nRespond with just the number of your choice.";
        
        auto response = Generate(prompt, 10);
        
        Json::Reader reader;
        Json::Value root;
        if (reader.parse(response, root)) {
            std::string text = root.get("response", "").asString();
            // Extract number from response
            for (char c : text) {
                if (c >= '1' && c <= '9') {
                    int idx = c - '1';
                    if (idx < static_cast<int>(options.size())) {
                        return options[idx];
                    }
                }
            }
        }
        
        return options.empty() ? "" : options[0];
    }
    
    ResourceMetrics GetResourceUsage() override {
        // Ollama doesn't expose resource metrics directly
        // We could try to query system metrics or parse from Ollama's API if available
        ResourceMetrics metrics;
        
        // Try to get from Ollama's ps endpoint
        auto response = HttpGet("/api/ps");
        Json::Reader reader;
        Json::Value root;
        if (reader.parse(response, root) && root.isMember("models")) {
            const auto& models = root["models"];
            for (const auto& model : models) {
                if (model.get("name", "").asString() == config_.ollama_model) {
                    // Extract VRAM if available
                    size_t size_vram = model.get("size_vram", 0).asUInt64();
                    metrics.vram_mb = size_vram / (1024.0 * 1024.0);
                    break;
                }
            }
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
        auto response = HttpGet("/api/tags");
        return !response.empty();
    }
    
    bool PullModelIfNeeded() {
        // Check if model exists
        auto response = HttpGet("/api/tags");
        Json::Reader reader;
        Json::Value root;
        if (reader.parse(response, root) && root.isMember("models")) {
            const auto& models = root["models"];
            for (const auto& model : models) {
                std::string name = model.get("name", "").asString();
                if (name == config_.ollama_model || name.find(config_.ollama_model) == 0) {
                    return true; // Model exists
                }
            }
        }
        
        // Model doesn't exist, try to pull it
        std::cout << "Pulling model: " << config_.ollama_model << "...\n";
        
        Json::Value request;
        request["name"] = config_.ollama_model;
        request["stream"] = false;
        
        auto pull_response = HttpPost("/api/pull", request);
        return !pull_response.empty();
    }
    
    std::string HttpGet(const std::string& endpoint) {
        std::string url = config_.ollama_url + endpoint;
        std::string response;
        
        curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl_, CURLOPT_TIMEOUT, 30L);
        
        CURLcode res = curl_easy_perform(curl_);
        curl_easy_reset(curl_);
        
        if (res != CURLE_OK) {
            return "";
        }
        
        return response;
    }
    
    std::string HttpPost(const std::string& endpoint, const Json::Value& json) {
        std::string url = config_.ollama_url + endpoint;
        std::string response;
        std::string post_data = json.toStyledString();
        
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        
        curl_easy_setopt(curl_, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl_, CURLOPT_POSTFIELDS, post_data.c_str());
        curl_easy_setopt(curl_, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl_, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl_, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl_, CURLOPT_TIMEOUT, 300L); // Longer timeout for generation
        
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
