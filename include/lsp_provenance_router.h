/**
 * LSP Provenance Router - Request/Response Lineage Tracking
 * 
 * Provides per-request lineage tracing for LSP operations:
 * - Request ID propagation
 * - File version binding
 * - Response validation
 * - FMF integration for fallback detection
 * 
 * This resolves the single most dangerous class of LSP failure:
 * "silent semantic degradation without runtime visibility"
 */

#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <atomic>
#include <chrono>
#include <functional>
#include <optional>
#include "FailureModeFirewall.h"
#include "FMF_LSP_Integration.h"

// Forward declaration
namespace nlohmann {
    class json;
}

// ============================================================================
// LSP Request Tracking Structures
// ============================================================================

/**
 * Unique identifier for an LSP request
 */
struct LSPRequestId {
    uint64_t id;
    std::string method;
    std::chrono::steady_clock::time_point timestamp;
    
    LSPRequestId() : id(0) {}
    LSPRequestId(uint64_t _id, const std::string& _method) 
        : id(_id), method(_method), timestamp(std::chrono::steady_clock::now()) {}
    
    bool operator==(const LSPRequestId& other) const { return id == other.id; }
    bool operator!=(const LSPRequestId& other) const { return id != other.id; }
};

/**
 * File version binding for request/response validation
 */
struct LSPFileVersion {
    std::string uri;
    int version;
    std::chrono::steady_clock::time_point timestamp;
    
    LSPFileVersion() : version(0) {}
    LSPFileVersion(const std::string& _uri, int _version) 
        : uri(_uri), version(_version), timestamp(std::chrono::steady_clock::now()) {}
};

/**
 * Cursor position for context tracking
 */
struct LSPCursorPosition {
    int line;
    int character;
    
    LSPCursorPosition() : line(0), character(0) {}
    LSPCursorPosition(int _line, int _char) : line(_line), character(_char) {}
};

/**
 * Complete request context
 */
struct LSPRequestContext {
    LSPRequestId requestId;
    LSPFileVersion fileVersion;
    LSPCursorPosition cursorPosition;
    std::string languageId;
    bool isValid;
    std::string validationError;
    
    LSPRequestContext() : isValid(false) {}
};

/**
 * Response provenance information
 */
struct LSPResponseProvenance {
    uint64_t requestId;
    std::string method;
    std::chrono::steady_clock::time_point requestTimestamp;
    std::chrono::steady_clock::time_point responseTimestamp;
    std::chrono::milliseconds latency;
    bool matched;
    bool stale;
    bool fallback;
    std::string fallbackReason;
    std::string executionPath; // "real" or "stub" or "fallback"
    
    LSPResponseProvenance() 
        : requestId(0), matched(false), stale(false), fallback(false) {}
};

/**
 * Callback types for provenance events
 */
using ProvenanceCallback = std::function<void(const LSPResponseProvenance&)>;
using ValidationErrorCallback = std::function<void(uint64_t requestId, const std::string& error)>;

// ============================================================================
// LSP Provenance Router
// ============================================================================

/**
 * LSP Provenance Router - Tracks request/response lineage
 * 
 * Thread-safe singleton for managing LSP request provenance
 */
class LSPProvenanceRouter {
public:
    // Singleton access
    static LSPProvenanceRouter& Instance();
    
    // Configuration
    void SetMaxPendingRequests(size_t maxRequests);
    void SetRequestTimeout(std::chrono::milliseconds timeout);
    void SetFileVersionValidation(bool enabled);
    
    // Request ID management
    uint64_t GenerateRequestId(const std::string& method);
    bool BindRequestToFile(uint64_t requestId, const std::string& uri, int version);
    bool BindRequestToCursor(uint64_t requestId, int line, int character);
    bool BindRequestToLanguage(uint64_t requestId, const std::string& languageId);
    
    // Request tracking
    bool TrackRequest(uint64_t requestId, const std::string& method);
    bool CompleteRequest(uint64_t requestId);
    bool CancelRequest(uint64_t requestId);
    
    // Response validation
    bool ValidateResponse(uint64_t requestId, const nlohmann::json& response);
    bool CheckFileVersion(uint64_t requestId, int currentVersion);
    bool CheckRequestMatch(uint64_t requestId, uint64_t responseId);
    
    // Provenance tracking
    LSPResponseProvenance GetProvenance(uint64_t requestId) const;
    std::vector<LSPResponseProvenance> GetRecentProvenance(size_t count = 100) const;
    
    // FMF integration
    void LogRealExecution(uint64_t requestId, const std::string& method);
    void LogFallbackExecution(uint64_t requestId, const std::string& method, const std::string& reason);
    void LogTimeout(uint64_t requestId, const std::string& method);
    
    // Statistics
    size_t GetPendingRequestCount() const;
    size_t GetTotalRequestCount() const;
    size_t GetMatchedResponseCount() const;
    size_t GetStaleResponseCount() const;
    size_t GetFallbackResponseCount() const;
    
    // Callbacks
    void SetProvenanceCallback(ProvenanceCallback callback);
    void SetValidationErrorCallback(ValidationErrorCallback callback);
    
    // Cleanup
    void CleanupStaleRequests();
    void Reset();
    
private:
    LSPProvenanceRouter();
    ~LSPProvenanceRouter() = default;
    LSPProvenanceRouter(const LSPProvenanceRouter&) = delete;
    LSPProvenanceRouter& operator=(const LSPProvenanceRouter&) = delete;
    
    void EnforceMaxPendingRequests();
    void RecordProvenance(const LSPResponseProvenance& provenance);
    
    mutable std::mutex m_mutex;
    std::atomic<uint64_t> m_nextRequestId{1};
    size_t m_maxPendingRequests{1000};
    std::chrono::milliseconds m_requestTimeout{30000}; // 30 seconds
    bool m_fileVersionValidation{true};
    
    // Pending requests
    std::unordered_map<uint64_t, LSPRequestContext> m_pendingRequests;
    
    // File version tracking
    std::unordered_map<std::string, int> m_currentFileVersions;
    
    // Provenance history
    std::vector<LSPResponseProvenance> m_provenanceHistory;
    size_t m_maxProvenanceHistory{1000};
    
    // Statistics
    std::atomic<size_t> m_totalRequests{0};
    std::atomic<size_t> m_matchedResponses{0};
    std::atomic<size_t> m_staleResponses{0};
    std::atomic<size_t> m_fallbackResponses{0};
    
    // Callbacks
    ProvenanceCallback m_provenanceCallback;
    ValidationErrorCallback m_validationErrorCallback;
};

// ============================================================================
// RAII Request Guard
// ============================================================================

/**
 * RAII guard for tracking LSP request lifetime
 */
class LSPRequestGuard {
public:
    LSPRequestGuard(const std::string& method);
    ~LSPRequestGuard();
    
    uint64_t GetRequestId() const { return m_requestId; }
    bool IsValid() const { return m_valid; }
    
    // Bind context
    void BindFile(const std::string& uri, int version);
    void BindCursor(int line, int character);
    void BindLanguage(const std::string& languageId);
    
private:
    uint64_t m_requestId;
    std::string m_method;
    bool m_valid;
};

// ============================================================================
// LSP Provenance Macros
// ============================================================================

// Track LSP request start
#define LSP_PROVENANCE_START(method) \
    LSPRequestGuard _lsp_guard(method); \
    uint64_t _lsp_request_id = _lsp_guard.GetRequestId(); \
    FMF_LSP_REAL_CALL(method)

// Track LSP request end
#define LSP_PROVENANCE_END(method) \
    LSPProvenanceRouter::Instance().CompleteRequest(_lsp_request_id)

// Track LSP fallback
#define LSP_PROVENANCE_FALLBACK(method, reason) \
    LSPProvenanceRouter::Instance().LogFallbackExecution(_lsp_request_id, method, reason); \
    FMF_LSP_FALLBACK_CALL(method, reason)

// Track LSP timeout
#define LSP_PROVENANCE_TIMEOUT(method) \
    LSPProvenanceRouter::Instance().LogTimeout(_lsp_request_id, method); \
    FMF_LSP_REQUEST_TIMEOUT(method, 30000)

// Validate LSP response
#define LSP_PROVENANCE_VALIDATE(response) \
    LSPProvenanceRouter::Instance().ValidateResponse(_lsp_request_id, response)