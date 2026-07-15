// ============================================================================
// sovereign_http_splitter_client.hpp - Phase 8: HTTP Splitter Client
// Batch splitter integration with HTTP decoder endpoint
// ============================================================================

#ifndef SOVEREIGN_HTTP_SPLITTER_CLIENT_HPP
#define SOVEREIGN_HTTP_SPLITTER_CLIENT_HPP

#include <windows.h>
#include <winsock2.h>
#include <string>
#include <vector>
#include <cstdint>

#pragma comment(lib, "ws2_32.lib")

namespace Sovereign {

// ============================================================================
// HTTP Splitter Client Configuration
// ============================================================================
struct SplitterClientConfig {
    std::string host = "localhost";
    int port = 8080;
    std::string endpoint = "/v1/decode";
    int timeout_ms = 30000;  // 30 second timeout
    int max_retries = 3;
    bool debug = false;
};

// ============================================================================
// Decode Request/Response
// ============================================================================
struct SplitterDecodeRequest {
    std::vector<int32_t> tokens;
    std::vector<int32_t> positions;
    float temperature = 0.8f;
    float top_p = 0.95f;
    int top_k = 40;
    int max_tokens = 1;
    bool return_logits = false;
    std::string model;
};

struct SplitterDecodeResponse {
    bool success = false;
    int error_code = 0;
    std::string error_message;
    std::vector<int32_t> output_tokens;
    std::vector<float> logits;
    int tokens_used = 0;
    int tokens_generated = 0;
    int http_status = 0;
};

// ============================================================================
// HTTP Splitter Client
// ============================================================================
class HTTPSplitterClient {
public:
    HTTPSplitterClient();
    ~HTTPSplitterClient();

    // Initialize Winsock and connection
    bool Initialize(const SplitterClientConfig& config);
    void Shutdown();

    // Send decode request to HTTP endpoint
    SplitterDecodeResponse Decode(const SplitterDecodeRequest& request);

    // Batch decode multiple token sequences
    std::vector<SplitterDecodeResponse> DecodeBatch(const std::vector<SplitterDecodeRequest>& requests);

    // Health check
    bool HealthCheck();

    // Getters
    bool IsInitialized() const { return initialized_; }
    const SplitterClientConfig& GetConfig() const { return config_; }

private:
    bool initialized_;
    SplitterClientConfig config_;
    SOCKET socket_;
    CRITICAL_SECTION cs_;  // Thread safety for socket operations

    // HTTP helpers
    bool Connect();
    void Disconnect();
    std::string BuildHttpRequest(const SplitterDecodeRequest& request);
    SplitterDecodeResponse ParseHttpResponse(const std::string& response);
    std::string SendHttpRequest(const std::string& request);
};

// ============================================================================
// Global Client Instance
// ============================================================================
// Get/set the global splitter client for Epoch-RCU integration
HTTPSplitterClient* GetGlobalSplitterClient();
void SetGlobalSplitterClient(HTTPSplitterClient* client);

// Convenience function for single decode
SplitterDecodeResponse HttpDecode(const std::vector<int32_t>& tokens, 
                                   const std::vector<int32_t>& positions = {},
                                   int max_tokens = 1);

} // namespace Sovereign

#endif // SOVEREIGN_HTTP_SPLITTER_CLIENT_HPP
