/**
 * APIClient.hpp
 *
 * Phase Q Batch 1/5: API Client SDK
 *
 * Type-safe C++ SDK for the RawrXD platform API with automatic
 * retry, caching, and connection pooling.
 */

#pragma once

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>
#include <future>

namespace SDK {

// ============================================================================
// Forward Declarations
// ============================================================================

class APIClient;
class RequestBuilder;
class ResponseHandler;
class ConnectionPool;
class RetryPolicy;

// ============================================================================
// HTTP Methods
// ============================================================================

enum class HTTPMethod {
    GET,
    POST,
    PUT,
    PATCH,
    DELETE,
    HEAD,
    OPTIONS
};

std::string HTTPMethodToString(HTTPMethod method);

// ============================================================================
// API Configuration
// ============================================================================

struct APIConfig {
    std::string baseUrl;
    std::optional<std::string> apiKey;
    std::optional<std::string> accessToken;
    std::optional<std::string> refreshToken;
    
    // Connection settings
    uint32_t connectionTimeoutMs = 30000;
    uint32_t requestTimeoutMs = 60000;
    uint32_t maxConnections = 10;
    bool keepAlive = true;
    
    // Retry settings
    uint32_t maxRetries = 3;
    std::chrono::milliseconds retryDelay{1000};
    std::chrono::milliseconds maxRetryDelay{30000};
    float retryBackoffMultiplier = 2.0f;
    
    // Cache settings
    bool enableCache = true;
    std::chrono::seconds defaultCacheTtl{300};
    size_t maxCacheSize = 100 * 1024 * 1024; // 100MB
    
    // TLS settings
    bool verifySSL = true;
    std::optional<std::string> caBundlePath;
    std::optional<std::string> clientCertPath;
    std::optional<std::string> clientKeyPath;
    
    // Rate limiting
    bool respectRateLimit = true;
    uint32_t requestsPerSecond = 100;
    
    // Logging
    bool enableLogging = false;
    std::optional<std::string> logFilePath;
};

// ============================================================================
// API Response
// ============================================================================

template<typename T>
class APIResponse {
public:
    bool success() const { return error_.has_value() == false; }
    bool failed() const { return error_.has_value(); }
    
    const T& data() const { return data_.value(); }
    const std::string& error() const { return error_.value(); }
    
    int statusCode() const { return statusCode_; }
    const std::map<std::string, std::string>& headers() const { return headers_; }
    std::optional<std::string> header(const std::string& name) const;
    
    std::chrono::milliseconds responseTime() const { return responseTime_; }
    bool fromCache() const { return fromCache_; }
    
    // Factory methods
    static APIResponse<T> Success(const T& data, int statusCode,
                                   const std::map<std::string, std::string>& headers,
                                   std::chrono::milliseconds responseTime);
    static APIResponse<T> Error(const std::string& error, int statusCode,
                                 std::chrono::milliseconds responseTime);
    static APIResponse<T> FromCache(const T& data);
    
private:
    std::optional<T> data_;
    std::optional<std::string> error_;
    int statusCode_;
    std::map<std::string, std::string> headers_;
    std::chrono::milliseconds responseTime_;
    bool fromCache_;
};

// ============================================================================
// Request Builder
// ============================================================================

class RequestBuilder {
public:
    explicit RequestBuilder(APIClient* client);
    
    // Method chaining
    RequestBuilder& Method(HTTPMethod method);
    RequestBuilder& Path(const std::string& path);
    RequestBuilder& Query(const std::string& key, const std::string& value);
    RequestBuilder& Header(const std::string& key, const std::string& value);
    RequestBuilder& Body(const std::string& body);
    RequestBuilder& Json(const std::string& json);
    RequestBuilder& FormData(const std::map<std::string, std::string>& data);
    RequestBuilder& FileUpload(const std::string& fieldName,
                                const std::string& filePath);
    
    // Authentication
    RequestBuilder& WithAPIKey(const std::string& apiKey);
    RequestBuilder& WithToken(const std::string& token);
    RequestBuilder& WithTenant(const std::string& tenantId);
    
    // Options
    RequestBuilder& Timeout(std::chrono::milliseconds timeout);
    RequestBuilder& NoRetry();
    RequestBuilder& NoCache();
    RequestBuilder& CacheTTL(std::chrono::seconds ttl);
    
    // Execution
    template<typename T>
    APIResponse<T> Execute();
    
    template<typename T>
    std::future<APIResponse<T>> ExecuteAsync();
    
    // Streaming
    using StreamCallback = std::function<void(const std::string& chunk)>;
    void ExecuteStream(StreamCallback callback);
    
private:
    APIClient* client_;
    HTTPMethod method_;
    std::string path_;
    std::map<std::string, std::string> queryParams_;
    std::map<std::string, std::string> headers_;
    std::optional<std::string> body_;
    std::optional<std::string> tenantId_;
    std::chrono::milliseconds timeout_;
    bool noRetry_;
    bool noCache_;
    std::optional<std::chrono::seconds> cacheTtl_;
};

// ============================================================================
// Pagination
// ============================================================================

template<typename T>
class PaginatedResult {
public:
    const std::vector<T>& items() const { return items_; }
    uint32_t totalCount() const { return totalCount_; }
    uint32_t pageSize() const { return pageSize_; }
    uint32_t currentPage() const { return currentPage_; }
    uint32_t totalPages() const { return (totalCount_ + pageSize_ - 1) / pageSize_; }
    
    bool hasNextPage() const { return currentPage_ < totalPages(); }
    bool hasPreviousPage() const { return currentPage_ > 1; }
    
    std::optional<std::string> nextCursor() const { return nextCursor_; }
    std::optional<std::string> previousCursor() const { return previousCursor_; }
    
    // Navigation
    APIResponse<PaginatedResult<T>> NextPage();
    APIResponse<PaginatedResult<T>> PreviousPage();
    APIResponse<PaginatedResult<T>> GoToPage(uint32_t page);
    
    // Iteration
    using Iterator = typename std::vector<T>::iterator;
    using ConstIterator = typename std::vector<T>::const_iterator;
    Iterator begin() { return items_.begin(); }
    Iterator end() { return items_.end(); }
    ConstIterator begin() const { return items_.begin(); }
    ConstIterator end() const { return items_.end(); }
    
private:
    std::vector<T> items_;
    uint32_t totalCount_;
    uint32_t pageSize_;
    uint32_t currentPage_;
    std::optional<std::string> nextCursor_;
    std::optional<std::string> previousCursor_;
    
    std::function<APIResponse<PaginatedResult<T>>(uint32_t)> pageFetcher_;
};

// ============================================================================
// Retry Policy
// ============================================================================

class RetryPolicy {
public:
    struct Config {
        uint32_t maxRetries = 3;
        std::chrono::milliseconds baseDelay{1000};
        std::chrono::milliseconds maxDelay{30000};
        float backoffMultiplier = 2.0f;
        std::vector<int> retryableStatusCodes = {408, 429, 500, 502, 503, 504};
        bool retryOnTimeout = true;
        bool retryOnNetworkError = true;
    };
    
    explicit RetryPolicy(const Config& config);
    
    bool ShouldRetry(int attempt, int statusCode, const std::string& error);
    std::chrono::milliseconds GetDelay(int attempt) const;
    void Reset();
    
private:
    Config config_;
    int currentAttempt_;
};

// ============================================================================
// Connection Pool
// ============================================================================

class ConnectionPool {
public:
    struct Config {
        uint32_t maxConnections = 10;
        uint32_t minConnections = 2;
        std::chrono::seconds connectionTimeout{30};
        std::chrono::seconds idleTimeout{300};
        bool enableKeepAlive = true;
    };
    
    explicit ConnectionPool(const Config& config);
    ~ConnectionPool();
    
    void Initialize(const std::string& baseUrl);
    void Shutdown();
    
    // Connection management
    void* AcquireConnection();
    void ReleaseConnection(void* connection);
    void InvalidateConnection(void* connection);
    
    // Statistics
    struct Stats {
        uint32_t activeConnections;
        uint32_t idleConnections;
        uint32_t totalConnections;
        uint64_t requestsServed;
        uint64_t connectionsCreated;
        uint64_t connectionsReused;
    };
    Stats GetStats() const;
    
private:
    Config config_;
    std::string baseUrl_;
    
    struct Connection {
        void* handle;
        std::chrono::system_clock::time_point lastUsed;
        bool inUse;
    };
    
    std::vector<Connection> connections_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    
    std::thread cleanupThread_;
    std::atomic<bool> stopCleanup_;
    
    void* CreateConnection();
    void CleanupLoop();
};

// ============================================================================
// Cache
// ============================================================================

class ResponseCache {
public:
    struct Config {
        size_t maxSize = 100 * 1024 * 1024; // 100MB
        std::chrono::seconds defaultTtl{300};
        bool respectCacheControl = true;
    };
    
    explicit ResponseCache(const Config& config);
    
    // Cache operations
    std::optional<std::string> Get(const std::string& key) const;
    void Put(const std::string& key, const std::string& value,
             std::optional<std::chrono::seconds> ttl = std::nullopt);
    void Invalidate(const std::string& key);
    void InvalidatePattern(const std::string& pattern);
    void Clear();
    
    // Statistics
    struct Stats {
        size_t currentSize;
        uint64_t hits;
        uint64_t misses;
        uint64_t evictions;
        double hitRate;
    };
    Stats GetStats() const;
    
private:
    Config config_;
    
    struct CacheEntry {
        std::string value;
        std::chrono::system_clock::time_point expiresAt;
        size_t size;
    };
    
    std::map<std::string, CacheEntry> cache_;
    size_t currentSize_;
    mutable std::mutex mutex_;
    
    uint64_t hits_;
    uint64_t misses_;
    uint64_t evictions_;
    
    void EvictIfNeeded(size_t requiredSpace);
    std::string MakeKey(const std::string& method,
                        const std::string& url,
                        const std::string& body) const;
};

// ============================================================================
// Rate Limiter
// ============================================================================

class RateLimiter {
public:
    explicit RateLimiter(uint32_t requestsPerSecond);
    
    bool Acquire();
    bool TryAcquire(std::chrono::milliseconds timeout);
    void Release();
    
    // Statistics
    uint32_t GetCurrentRate() const;
    uint32_t GetQueueSize() const;
    
private:
    uint32_t requestsPerSecond_;
    std::queue<std::chrono::system_clock::time_point> requestTimes_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
};

// ============================================================================
// API Client
// ============================================================================

class APIClient {
public:
    explicit APIClient(const APIConfig& config);
    ~APIClient();
    
    // Lifecycle
    bool Initialize();
    void Shutdown();
    bool IsInitialized() const;
    
    // Request building
    RequestBuilder Request();
    RequestBuilder Get(const std::string& path);
    RequestBuilder Post(const std::string& path);
    RequestBuilder Put(const std::string& path);
    RequestBuilder Patch(const std::string& path);
    RequestBuilder Delete(const std::string& path);
    
    // Authentication
    void SetAPIKey(const std::string& apiKey);
    void SetAccessToken(const std::string& token);
    void SetRefreshToken(const std::string& token);
    APIResponse<std::string> RefreshAccessToken();
    
    // Tenant context
    void SetTenantContext(const std::string& tenantId);
    void ClearTenantContext();
    
    // Batch operations
    template<typename T>
    std::vector<APIResponse<T>> ExecuteBatch(
        const std::vector<std::function<APIResponse<T>()>>& requests);
    
    // WebSocket
    using WebSocketMessageHandler = std::function<void(const std::string& message)>;
    using WebSocketErrorHandler = std::function<void(const std::string& error)>;
    
    bool ConnectWebSocket(const std::string& path,
                          WebSocketMessageHandler onMessage,
                          WebSocketErrorHandler onError);
    void DisconnectWebSocket();
    void SendWebSocketMessage(const std::string& message);
    bool IsWebSocketConnected() const;
    
    // Event streaming (SSE)
    using EventHandler = std::function<void(const std::string& event,
                                             const std::string& data)>;
    void SubscribeToEvents(const std::string& channel, EventHandler handler);
    void UnsubscribeFromEvents(const std::string& channel);
    
    // Statistics
    struct Stats {
        uint64_t totalRequests;
        uint64_t successfulRequests;
        uint64_t failedRequests;
        uint64_t retriedRequests;
        uint64_t cachedResponses;
        double averageResponseTimeMs;
        std::map<int, uint64_t> statusCodeDistribution;
    };
    Stats GetStats() const;
    void ResetStats();
    
    // Error handling
    using ErrorHandler = std::function<void(const std::string& error,
                                             int statusCode)>;
    void SetErrorHandler(ErrorHandler handler);
    
private:
    APIConfig config_;
    bool initialized_;
    
    std::unique_ptr<ConnectionPool> connectionPool_;
    std::unique_ptr<ResponseCache> cache_;
    std::unique_ptr<RetryPolicy> retryPolicy_;
    std::unique_ptr<RateLimiter> rateLimiter_;
    
    std::string currentTenantId_;
    mutable std::mutex tenantMutex_;
    
    Stats stats_;
    mutable std::mutex statsMutex_;
    
    ErrorHandler errorHandler_;
    
    // Internal request execution
    template<typename T>
    APIResponse<T> ExecuteRequest(const RequestBuilder& request);
    
    void UpdateStats(const APIResponse<void>& response);
    std::string BuildUrl(const std::string& path,
                           const std::map<std::string, std::string>& queryParams) const;
};

// ============================================================================
// Service Clients
// ============================================================================

class TenantServiceClient {
public:
    explicit TenantServiceClient(APIClient* client);
    
    // Tenant operations
    APIResponse<std::string> CreateTenant(const std::string& name,
                                             const std::string& planId);
    APIResponse<void> DeleteTenant(const std::string& tenantId);
    APIResponse<TenantInfo> GetTenant(const std::string& tenantId);
    APIResponse<PaginatedResult<TenantInfo>> ListTenants(uint32_t page = 1,
                                                           uint32_t pageSize = 20);
    APIResponse<void> UpdateTenant(const std::string& tenantId,
                                    const std::map<std::string, std::string>& updates);
    
private:
    APIClient* client_;
};

class InferenceServiceClient {
public:
    explicit InferenceServiceClient(APIClient* client);
    
    // Model operations
    APIResponse<ModelInfo> LoadModel(const std::string& modelId);
    APIResponse<void> UnloadModel(const std::string& modelId);
    APIResponse<PaginatedResult<ModelInfo>> ListModels();
    
    // Inference
    APIResponse<InferenceResult> RunInference(const std::string& modelId,
                                               const std::vector<float>& input);
    APIResponse<StreamingInferenceResult> StreamInference(
        const std::string& modelId,
        const std::vector<float>& input);
    
    // Batch inference
    APIResponse<std::vector<InferenceResult>> BatchInference(
        const std::string& modelId,
        const std::vector<std::vector<float>>& inputs);
    
private:
    APIClient* client_;
};

class WorkflowServiceClient {
public:
    explicit WorkflowServiceClient(APIClient* client);
    
    // Workflow operations
    APIResponse<std::string> StartWorkflow(const std::string& workflowId,
                                              const std::map<std::string, std::any>& inputs);
    APIResponse<WorkflowStatus> GetWorkflowStatus(const std::string& executionId);
    APIResponse<void> CancelWorkflow(const std::string& executionId);
    APIResponse<PaginatedResult<WorkflowExecution>> ListWorkflowExecutions(
        const std::string& workflowId);
    
private:
    APIClient* client_;
};

} // namespace SDK
