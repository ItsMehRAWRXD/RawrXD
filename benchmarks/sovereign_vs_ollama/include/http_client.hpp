// HTTP Client Infrastructure
// Provides HTTP/HTTPS communication for backend adapters
// Copyright (c) 2026 RawrXD Team

#pragma once

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <memory>
#include <chrono>

// Platform-specific includes
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netdb.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

namespace rawrxd::benchmark {

// ============================================================================
// HTTP Response
// ============================================================================
struct HttpResponse {
    int status_code = 0;
    std::string status_text;
    std::map<std::string, std::string> headers;
    std::string body;
    double latency_ms = 0.0;
    bool success = false;
    std::string error_message;
    
    bool IsSuccess() const { return success && status_code >= 200 && status_code < 300; }
    bool IsRedirect() const { return status_code >= 300 && status_code < 400; }
    bool IsClientError() const { return status_code >= 400 && status_code < 500; }
    bool IsServerError() const { return status_code >= 500 && status_code < 600; }
    
    std::string GetHeader(const std::string& name) const {
        auto it = headers.find(name);
        return it != headers.end() ? it->second : "";
    }
};

// ============================================================================
// HTTP Request
// ============================================================================
struct HttpRequest {
    std::string method = "GET";
    std::string url;
    std::map<std::string, std::string> headers;
    std::string body;
    std::string content_type = "application/json";
    
    // Timeout settings
    int connect_timeout_ms = 5000;
    int read_timeout_ms = 30000;
    int total_timeout_ms = 60000;
    
    // Retry settings
    int max_retries = 3;
    int retry_delay_ms = 1000;
    bool use_exponential_backoff = true;
    
    void SetHeader(const std::string& name, const std::string& value) {
        headers[name] = value;
    }
    
    void SetJsonBody(const std::string& json) {
        body = json;
        content_type = "application/json";
        headers["Content-Type"] = content_type;
        headers["Content-Length"] = std::to_string(body.length());
    }
};

// ============================================================================
// Connection Pool
// ============================================================================
class ConnectionPool {
public:
    struct Connection {
        int socket_fd = -1;
        std::string host;
        int port = 0;
        TimePoint last_used;
        bool in_use = false;
        int use_count = 0;
    };
    
    ConnectionPool(size_t max_connections = 10, 
                   int connection_timeout_ms = 5000,
                   int idle_timeout_ms = 30000);
    ~ConnectionPool();
    
    // Get connection from pool
    std::shared_ptr<Connection> Acquire(const std::string& host, int port);
    
    // Return connection to pool
    void Release(std::shared_ptr<Connection> conn);
    
    // Close all connections
    void CloseAll();
    
    // Get pool statistics
    struct Stats {
        size_t total_connections = 0;
        size_t active_connections = 0;
        size_t idle_connections = 0;
        size_t total_requests = 0;
        size_t cache_hits = 0;
        size_t cache_misses = 0;
    };
    Stats GetStats() const;
    
private:
    std::vector<std::shared_ptr<Connection>> connections_;
    size_t max_connections_;
    int connection_timeout_ms_;
    int idle_timeout_ms_;
    mutable std::mutex mutex_;
    
    std::shared_ptr<Connection> CreateConnection(const std::string& host, int port);
    void CleanupIdleConnections();
};

// ============================================================================
// HTTP Client
// ============================================================================
class HttpClient {
public:
    HttpClient();
    ~HttpClient();
    
    // Initialize (call before first request)
    bool Initialize();
    void Shutdown();
    
    // Synchronous request
    HttpResponse Request(const HttpRequest& request);
    
    // Convenience methods
    HttpResponse Get(const std::string& url, 
                     const std::map<std::string, std::string>& headers = {});
    HttpResponse Post(const std::string& url, 
                      const std::string& body,
                      const std::map<std::string, std::string>& headers = {});
    HttpResponse PostJson(const std::string& url,
                          const std::string& json_body,
                          const std::map<std::string, std::string>& headers = {});
    
    // Configuration
    void SetDefaultTimeout(int connect_ms, int read_ms, int total_ms);
    void SetRetryPolicy(int max_retries, int delay_ms, bool exponential);
    void SetUserAgent(const std::string& user_agent);
    
    // Connection pool
    void EnableConnectionPool(size_t max_connections = 10);
    void DisableConnectionPool();
    
    // Statistics
    struct Stats {
        uint64_t total_requests = 0;
        uint64_t successful_requests = 0;
        uint64_t failed_requests = 0;
        uint64_t retried_requests = 0;
        double average_latency_ms = 0.0;
        double min_latency_ms = 0.0;
        double max_latency_ms = 0.0;
    };
    Stats GetStats() const;
    void ResetStats();
    
private:
    bool initialized_ = false;
    std::string user_agent_ = "RawrXD-Benchmark/2.0";
    
    // Default timeouts
    int default_connect_timeout_ms_ = 5000;
    int default_read_timeout_ms_ = 30000;
    int default_total_timeout_ms_ = 60000;
    
    // Retry policy
    int default_max_retries_ = 3;
    int default_retry_delay_ms_ = 1000;
    bool default_exponential_backoff_ = true;
    
    // Connection pool
    std::unique_ptr<ConnectionPool> connection_pool_;
    bool use_connection_pool_ = false;
    
    // Statistics
    mutable std::mutex stats_mutex_;
    Stats stats_;
    
    // Internal methods
    HttpResponse ExecuteRequest(const HttpRequest& request);
    HttpResponse ExecuteWithRetry(const HttpRequest& request);
    bool ParseUrl(const std::string& url, std::string& host, int& port, std::string& path, bool& use_https);
    std::string BuildRequestString(const HttpRequest& request, const std::string& host, const std::string& path);
    HttpResponse ParseResponse(const std::string& response_data);
    void UpdateStats(const HttpResponse& response);
    
    // Platform-specific
    #ifdef _WIN32
        WSADATA wsa_data_;
    #endif
};

// ============================================================================
// Retry Policy
// ============================================================================
class RetryPolicy {
public:
    RetryPolicy(int max_retries = 3, 
                int base_delay_ms = 1000,
                bool exponential = true,
                double backoff_multiplier = 2.0,
                int max_delay_ms = 30000);
    
    // Check if request should be retried
    bool ShouldRetry(int attempt_number, const HttpResponse& response);
    
    // Calculate delay before next attempt
    int GetDelayMs(int attempt_number) const;
    
    // Check if error is retryable
    static bool IsRetryableError(const HttpResponse& response);
    static bool IsRetryableException(const std::exception& e);
    
private:
    int max_retries_;
    int base_delay_ms_;
    bool exponential_;
    double backoff_multiplier_;
    int max_delay_ms_;
};

// ============================================================================
// Timeout Manager
// ============================================================================
class TimeoutManager {
public:
    TimeoutManager(int connect_ms, int read_ms, int total_ms);
    
    // Set socket timeouts
    bool SetSocketTimeouts(int socket_fd);
    
    // Check if operation timed out
    bool IsTimedOut() const;
    
    // Get remaining time
    int GetRemainingTimeMs() const;
    
    // Reset timers
    void Reset();
    
private:
    int connect_timeout_ms_;
    int read_timeout_ms_;
    int total_timeout_ms_;
    TimePoint start_time_;
    
    #ifdef _WIN32
        DWORD GetTimeoutValue(int ms);
    #endif
};

// ============================================================================
// Utility Functions
// ============================================================================
namespace http {
    // URL encoding/decoding
    std::string UrlEncode(const std::string& value);
    std::string UrlDecode(const std::string& value);
    
    // Header utilities
    std::string NormalizeHeaderName(const std::string& name);
    std::map<std::string, std::string> ParseHeaders(const std::string& header_section);
    
    // Status code utilities
    const char* GetStatusText(int status_code);
    bool IsInformational(int status_code);
    bool IsSuccess(int status_code);
    bool IsRedirect(int status_code);
    bool IsClientError(int status_code);
    bool IsServerError(int status_code);
}

} // namespace rawrxd::benchmark
