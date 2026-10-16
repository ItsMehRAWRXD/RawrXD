// cloud_api_client.h - Universal Cloud API Client for Multiple Providers
// Pure Windows native implementation using WinHTTP (no Qt dependency)
#ifndef CLOUD_API_CLIENT_H
#define CLOUD_API_CLIENT_H

#include <string>
#include <map>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>
#include <cstdint>

#include "universal_model_router.h"

// Structured logging
struct ApiCallLog {
    std::string timestamp;
    std::string provider;
    std::string model;
    std::string endpoint;
    std::string request_body;
    std::string response_body;
    int status_code;
    int64_t latency_ms;
    bool success;
    std::string error_message;
};

// API response structure
struct ApiResponse {
    bool success = false;
    std::string content;
    int status_code = 0;
    std::string raw_body;
    int64_t latency_ms = 0;
    std::string error_message;
    std::map<std::string, std::string> metadata;
};

// Cloud API Client - dependency-free Windows native implementation
class CloudApiClient {
public:
    explicit CloudApiClient();
    ~CloudApiClient();

    // Synchronous generation (blocking)
    std::string generate(const std::string& prompt, const ModelConfig& config);

    // Asynchronous generation
    void generateAsync(const std::string& prompt,
                       const ModelConfig& config,
                       std::function<void(const ApiResponse&)> callback);

    // Provider health check
    bool checkProviderHealth(const ModelConfig& config);

    // Model listing
    std::vector<std::string> listModels(const ModelConfig& config);

    // Logging and metrics
    std::vector<ApiCallLog> getCallHistory() const;
    void clearCallHistory();
    ApiCallLog getLastCall() const;
    double getAverageLatency() const;
    int getSuccessRate() const;  // 0-100

private:
    // API request execution using WinHTTP
    ApiResponse executeRequest(const std::string& endpoint,
                               const std::string& method,
                               const std::string& body,
                               const std::string& api_key,
                               const std::map<std::string, std::string>& headers = {});

    // Request building by backend
    std::string buildOpenAICompatibleRequest(const std::string& prompt, const ModelConfig& config);
    std::string buildOpenRouterRequest(const std::string& prompt, const ModelConfig& config);

    // Response parsing
    std::string parseOpenAIResponse(const std::string& raw_body);

    // Endpoint definitions
    struct ApiEndpoint {
        std::string base_url;
        std::string chat_endpoint;
        std::string model_list_endpoint;
    };

    // API endpoint definitions keyed by ModelBackend enum value
    std::map<int, ApiEndpoint> api_endpoints;

    // Initialize endpoint table
    void initializeApiEndpoints();

    // Call history and metrics
    std::vector<ApiCallLog> call_history;
    static const int MAX_HISTORY_SIZE = 1000;

    // Error handling
    std::string formatErrorResponse(int status_code, const std::string& body);
    void logApiCall(const ApiCallLog& log);
    std::string currentTimestamp();
};

#endif // CLOUD_API_CLIENT_H
