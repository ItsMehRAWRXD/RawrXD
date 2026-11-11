// ollama_adapter.hpp
// HTTP adapter for Ollama API

#ifndef OLLAMA_ADAPTER_HPP
#define OLLAMA_ADAPTER_HPP

#include "benchmark_common.hpp"
#include <string>
#include <memory>
#include <chrono>

// Forward declare CURL
typedef void CURL;

namespace Benchmark {
namespace Backends {

// Ollama-specific request structures
struct OllamaGenerateRequest {
    std::string model;
    std::string prompt;
    float temperature = 0.0f;
    int num_predict = 256;
    std::optional<int> seed;
    bool stream = false;
};

struct OllamaGenerateResult {
    bool success = false;
    std::string error_message;
    
    // Timing
    double total_duration_ms = 0.0;
    double load_duration_ms = 0.0;
    double prompt_eval_duration_ms = 0.0;
    double eval_duration_ms = 0.0;
    
    // Throughput
    int prompt_eval_count = 0;
    int eval_count = 0;
    double tokens_per_second = 0.0;
    
    // Output
    std::string response;
};

// Ollama Adapter Class
class OllamaAdapter {
public:
    explicit OllamaAdapter(const std::string& base_url = "http://localhost:11434");
    ~OllamaAdapter();
    
    // Connection
    bool IsAvailable();
    std::string GetBackendName() const;
    std::string GetBackendVersion();
    
    // Core operations
    OllamaGenerateResult Generate(const OllamaGenerateRequest& request);
    
    // Conversion to common format
    InferenceResult ToInferenceResult(const OllamaGenerateResult& result);
    
private:
    std::string base_url_;
    CURL* curl_;
    
    // HTTP helpers
    bool HttpGet(const std::string& endpoint, std::string& response);
    bool HttpPost(const std::string& endpoint, const std::string& json_body, std::string& response);
    
    // Response parsers
    OllamaGenerateResult ParseGenerateResponse(const std::string& json);
    std::string ParseVersion(const std::string& json);
    
    // Utilities
    std::string EscapeJson(const std::string& input);
};

} // namespace Backends
} // namespace Benchmark

#endif // OLLAMA_ADAPTER_HPP
