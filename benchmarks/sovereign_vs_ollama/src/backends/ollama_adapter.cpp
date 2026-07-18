// ollama_adapter.cpp
// HTTP adapter for Ollama API (localhost:11434)

#include "backends/ollama_adapter.hpp"
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

OllamaAdapter::OllamaAdapter(const std::string& base_url)
    : base_url_(base_url), curl_(nullptr) {
    curl_ = curl_easy_init();
    if (!curl_) {
        throw std::runtime_error("Failed to initialize CURL");
    }
}

OllamaAdapter::~OllamaAdapter() {
    if (curl_) {
        curl_easy_cleanup(curl_);
    }
}

bool OllamaAdapter::IsAvailable() {
    std::string response;
    return HttpGet("/api/tags", response);
}

std::string OllamaAdapter::GetBackendName() const {
    return "Ollama";
}

std::string OllamaAdapter::GetBackendVersion() {
    std::string response;
    if (HttpGet("/api/version", response)) {
        return ParseVersion(response);
    }
    return "unknown";
}

OllamaGenerateResult OllamaAdapter::Generate(const OllamaGenerateRequest& request) {
    OllamaGenerateResult result;
    result.success = false;
    
    // Build JSON request
    std::stringstream json;
    json << "{";
    json << "\"model\":\"" << request.model << "\",";
    json << "\"prompt\":\"" << EscapeJson(request.prompt) << "\",";
    json << "\"temperature\":" << request.temperature << ",";
    json << "\"num_predict\":" << request.num_predict << ",";
    json << "\"stream\":" << (request.stream ? "true" : "false");
    if (request.seed.has_value()) {
        json << ",\"seed\":" << request.seed.value();
    }
    json << "}";
    
    std::string response;
    auto start = std::chrono::high_resolution_clock::now();
    
    bool http_success = HttpPost("/api/generate", json.str(), response);
    
    auto end = std::chrono::high_resolution_clock::now();
    result.total_duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    if (!http_success) {
        result.error_message = "HTTP request failed";
        return result;
    }
    
    // Parse response
    result = ParseGenerateResponse(response);
    
    return result;
}

InferenceResult OllamaAdapter::ToInferenceResult(const OllamaGenerateResult& ollama_result) {
    InferenceResult result;
    result.success = ollama_result.success;
    result.error_message = ollama_result.error_message;
    
    // Map Ollama timing to common format
    result.time_to_first_token_ms = ollama_result.load_duration_ms + ollama_result.prompt_eval_duration_ms;
    result.total_latency_ms = ollama_result.total_duration_ms;
    
    // Map throughput
    result.tokens_generated = ollama_result.eval_count;
    result.tokens_per_second = ollama_result.tokens_per_second;
    
    // Map output
    result.generated_text = ollama_result.response;
    
    return result;
}

bool OllamaAdapter::HttpGet(const std::string& endpoint, std::string& response) {
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

bool OllamaAdapter::HttpPost(const std::string& endpoint, 
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
    curl_easy_setopt(curl_, CURLOPT_TIMEOUT, 300L);
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

OllamaGenerateResult OllamaAdapter::ParseGenerateResponse(const std::string& json) {
    OllamaGenerateResult result;
    result.success = true;
    
    // Simple JSON parsing
    size_t response_pos = json.find("\"response\":\"");
    if (response_pos != std::string::npos) {
        size_t end_pos = json.find("\"", response_pos + 12);
        if (end_pos != std::string::npos) {
            result.response = json.substr(response_pos + 12, end_pos - response_pos - 12);
        }
    }
    
    size_t total_pos = json.find("\"total_duration\":");
    if (total_pos != std::string::npos) {
        // Ollama returns nanoseconds, convert to ms
        result.total_duration_ms = std::stoll(json.substr(total_pos + 18)) / 1e6;
    }
    
    size_t load_pos = json.find("\"load_duration\":");
    if (load_pos != std::string::npos) {
        result.load_duration_ms = std::stoll(json.substr(load_pos + 17)) / 1e6;
    }
    
    size_t prompt_pos = json.find("\"prompt_eval_duration\":");
    if (prompt_pos != std::string::npos) {
        result.prompt_eval_duration_ms = std::stoll(json.substr(prompt_pos + 23)) / 1e6;
    }
    
    size_t eval_pos = json.find("\"eval_duration\":");
    if (eval_pos != std::string::npos) {
        result.eval_duration_ms = std::stoll(json.substr(eval_pos + 17)) / 1e6;
    }
    
    size_t prompt_count_pos = json.find("\"prompt_eval_count\":");
    if (prompt_count_pos != std::string::npos) {
        result.prompt_eval_count = std::stoi(json.substr(prompt_count_pos + 21));
    }
    
    size_t eval_count_pos = json.find("\"eval_count\":");
    if (eval_count_pos != std::string::npos) {
        result.eval_count = std::stoi(json.substr(eval_count_pos + 14));
    }
    
    // Calculate TPS
    if (result.eval_duration_ms > 0 && result.eval_count > 0) {
        result.tokens_per_second = (result.eval_count / result.eval_duration_ms) * 1000.0;
    }
    
    return result;
}

std::string OllamaAdapter::ParseVersion(const std::string& json) {
    size_t ver_pos = json.find("\"version\":\"");
    if (ver_pos != std::string::npos) {
        size_t end_pos = json.find("\"", ver_pos + 11);
        if (end_pos != std::string::npos) {
            return json.substr(ver_pos + 11, end_pos - ver_pos - 11);
        }
    }
    return "unknown";
}

std::string OllamaAdapter::EscapeJson(const std::string& input) {
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
