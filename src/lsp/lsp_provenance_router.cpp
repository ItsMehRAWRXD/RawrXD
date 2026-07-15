/**
 * LSP Provenance Router - Implementation
 * 
 * Request/response lineage tracking for LSP operations
 */

#include "lsp_provenance_router.h"
#include <nlohmann/json.hpp>
#include <algorithm>
#include <sstream>

// Singleton instance
LSPProvenanceRouter& LSPProvenanceRouter::Instance() {
    static LSPProvenanceRouter instance;
    return instance;
}

LSPProvenanceRouter::LSPProvenanceRouter() {
    // Initialize with defaults
    m_nextRequestId = 1;
    m_maxPendingRequests = 1000;
    m_requestTimeout = std::chrono::milliseconds(30000);
    m_fileVersionValidation = true;
    m_maxProvenanceHistory = 1000;
}

// ============================================================================
// Configuration
// ============================================================================

void LSPProvenanceRouter::SetMaxPendingRequests(size_t maxRequests) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_maxPendingRequests = maxRequests;
}

void LSPProvenanceRouter::SetRequestTimeout(std::chrono::milliseconds timeout) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_requestTimeout = timeout;
}

void LSPProvenanceRouter::SetFileVersionValidation(bool enabled) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_fileVersionValidation = enabled;
}

// ============================================================================
// Request ID Management
// ============================================================================

uint64_t LSPProvenanceRouter::GenerateRequestId(const std::string& method) {
    uint64_t id = m_nextRequestId.fetch_add(1);
    
    // Track the request
    TrackRequest(id, method);
    
    // Report to FMF - use method.c_str() for const char*
    FailureModeFirewall::Instance().ReportRealExecution(method.c_str(), __FILE__, __FUNCTION__);
    
    return id;
}

bool LSPProvenanceRouter::BindRequestToFile(uint64_t requestId, const std::string& uri, int version) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_pendingRequests.find(requestId);
    if (it == m_pendingRequests.end()) {
        return false;
    }
    
    it->second.fileVersion = LSPFileVersion(uri, version);
    return true;
}

bool LSPProvenanceRouter::BindRequestToCursor(uint64_t requestId, int line, int character) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_pendingRequests.find(requestId);
    if (it == m_pendingRequests.end()) {
        return false;
    }
    
    it->second.cursorPosition = LSPCursorPosition(line, character);
    return true;
}

bool LSPProvenanceRouter::BindRequestToLanguage(uint64_t requestId, const std::string& languageId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_pendingRequests.find(requestId);
    if (it == m_pendingRequests.end()) {
        return false;
    }
    
    it->second.languageId = languageId;
    return true;
}

// ============================================================================
// Request Tracking
// ============================================================================

bool LSPProvenanceRouter::TrackRequest(uint64_t requestId, const std::string& method) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Enforce max pending requests
    EnforceMaxPendingRequests();
    
    LSPRequestContext context;
    context.requestId = LSPRequestId(requestId, method);
    context.isValid = true;
    
    m_pendingRequests[requestId] = context;
    m_totalRequests++;
    
    return true;
}

bool LSPProvenanceRouter::CompleteRequest(uint64_t requestId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_pendingRequests.find(requestId);
    if (it == m_pendingRequests.end()) {
        return false;
    }
    
    m_pendingRequests.erase(it);
    return true;
}

bool LSPProvenanceRouter::CancelRequest(uint64_t requestId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_pendingRequests.find(requestId);
    if (it == m_pendingRequests.end()) {
        return false;
    }
    
    // Log cancellation as fallback
    LogFallbackExecution(requestId, it->second.requestId.method, "REQUEST_CANCELLED");
    
    m_pendingRequests.erase(it);
    return true;
}

// ============================================================================
// Response Validation
// ============================================================================

bool LSPProvenanceRouter::ValidateResponse(uint64_t requestId, const nlohmann::json& response) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_pendingRequests.find(requestId);
    if (it == m_pendingRequests.end()) {
        // Request not found - stale response
        if (m_validationErrorCallback) {
            m_validationErrorCallback(requestId, "REQUEST_NOT_FOUND");
        }
        return false;
    }
    
    const auto& context = it->second;
    
    // Check if response has matching ID
    if (response.contains("id")) {
        uint64_t responseId = response["id"].get<uint64_t>();
        if (responseId != requestId) {
            // ID mismatch
            if (m_validationErrorCallback) {
                std::stringstream ss;
                ss << "ID_MISMATCH: expected " << requestId << ", got " << responseId;
                m_validationErrorCallback(requestId, ss.str());
            }
            
            // Log to FMF
            FMF_LSP_RequestIdMismatch(static_cast<int>(requestId), static_cast<int>(responseId));
            
            return false;
        }
    }
    
    // Check for error response
    if (response.contains("error")) {
        const auto& error = response["error"];
        std::string errorMsg = error.contains("message") ? 
            error["message"].get<std::string>() : "UNKNOWN_ERROR";
        
        if (m_validationErrorCallback) {
            m_validationErrorCallback(requestId, errorMsg);
        }
        
        // Log to FMF
        FMF_LSP_ResponseParseError(context.requestId.method.c_str());
        
        return false;
    }
    
    // Validate file version if enabled
    if (m_fileVersionValidation && !context.fileVersion.uri.empty()) {
        auto versionIt = m_currentFileVersions.find(context.fileVersion.uri);
        if (versionIt != m_currentFileVersions.end()) {
            if (versionIt->second != context.fileVersion.version) {
                // Version mismatch - stale response
                if (m_validationErrorCallback) {
                    std::stringstream ss;
                    ss << "VERSION_MISMATCH: expected " << context.fileVersion.version 
                       << ", current " << versionIt->second;
                    m_validationErrorCallback(requestId, ss.str());
                }
                
                // Log to FMF
                FMF_LSP_VersionMismatch(context.fileVersion.version, versionIt->second);
                
                m_staleResponses++;
                return false;
            }
        }
    }
    
    // Success - record provenance
    LSPResponseProvenance provenance;
    provenance.requestId = requestId;
    provenance.method = context.requestId.method;
    provenance.requestTimestamp = context.requestId.timestamp;
    provenance.responseTimestamp = std::chrono::steady_clock::now();
    provenance.latency = std::chrono::duration_cast<std::chrono::milliseconds>(
        provenance.responseTimestamp - provenance.requestTimestamp);
    provenance.matched = true;
    provenance.stale = false;
    provenance.fallback = false;
    provenance.executionPath = "real";
    
    RecordProvenance(provenance);
    m_matchedResponses++;
    
    // Complete the request
    m_pendingRequests.erase(it);
    
    return true;
}

bool LSPProvenanceRouter::CheckFileVersion(uint64_t requestId, int currentVersion) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_pendingRequests.find(requestId);
    if (it == m_pendingRequests.end()) {
        return false;
    }
    
    if (it->second.fileVersion.version != currentVersion) {
        FMF_LSP_VersionMismatch(it->second.fileVersion.version, currentVersion);
        return false;
    }
    
    return true;
}

bool LSPProvenanceRouter::CheckRequestMatch(uint64_t requestId, uint64_t responseId) {
    if (requestId != responseId) {
        FMF_LSP_RequestIdMismatch(static_cast<int>(requestId), static_cast<int>(responseId));
        return false;
    }
    return true;
}

// ============================================================================
// Provenance Tracking
// ============================================================================

LSPResponseProvenance LSPProvenanceRouter::GetProvenance(uint64_t requestId) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Search in history
    for (const auto& prov : m_provenanceHistory) {
        if (prov.requestId == requestId) {
            return prov;
        }
    }
    
    // Not found
    LSPResponseProvenance empty;
    empty.requestId = requestId;
    empty.matched = false;
    return empty;
}

std::vector<LSPResponseProvenance> LSPProvenanceRouter::GetRecentProvenance(size_t count) const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<LSPResponseProvenance> result;
    size_t start = m_provenanceHistory.size() > count ? m_provenanceHistory.size() - count : 0;
    
    for (size_t i = start; i < m_provenanceHistory.size(); ++i) {
        result.push_back(m_provenanceHistory[i]);
    }
    
    return result;
}

// ============================================================================
// FMF Integration
// ============================================================================

void LSPProvenanceRouter::LogRealExecution(uint64_t requestId, const std::string& method) {
    FailureModeFirewall::Instance().ReportRealExecution(method.c_str(), __FILE__, __FUNCTION__);
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Update provenance if request exists
    auto it = m_pendingRequests.find(requestId);
    if (it != m_pendingRequests.end()) {
        // Mark as real execution in context
        // (provenance will be recorded when response arrives)
    }
}

void LSPProvenanceRouter::LogFallbackExecution(uint64_t requestId, const std::string& method, const std::string& reason) {
    FailureModeFirewall::Instance().ReportFallback(reason.c_str(), __FILE__, __LINE__);
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Record fallback provenance
    LSPResponseProvenance provenance;
    provenance.requestId = requestId;
    provenance.method = method;
    provenance.requestTimestamp = std::chrono::steady_clock::now();
    provenance.responseTimestamp = provenance.requestTimestamp;
    provenance.matched = false;
    provenance.fallback = true;
    provenance.fallbackReason = reason;
    provenance.executionPath = "fallback";
    
    RecordProvenance(provenance);
    m_fallbackResponses++;
    
    // Remove from pending
    m_pendingRequests.erase(requestId);
}

void LSPProvenanceRouter::LogTimeout(uint64_t requestId, const std::string& method) {
    char reason[256];
    snprintf(reason, sizeof(reason), "LSP_TIMEOUT_%s_%lldms", method.c_str(), static_cast<long long>(m_requestTimeout.count()));
    FailureModeFirewall::Instance().ReportFallback(reason, __FILE__, __LINE__);
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    // Record timeout provenance
    LSPResponseProvenance provenance;
    provenance.requestId = requestId;
    provenance.method = method;
    provenance.requestTimestamp = std::chrono::steady_clock::now() - m_requestTimeout;
    provenance.responseTimestamp = std::chrono::steady_clock::now();
    provenance.matched = false;
    provenance.fallback = true;
    provenance.fallbackReason = "TIMEOUT";
    provenance.executionPath = "timeout";
    
    RecordProvenance(provenance);
    m_fallbackResponses++;
    
    // Remove from pending
    m_pendingRequests.erase(requestId);
}

// ============================================================================
// Statistics
// ============================================================================

size_t LSPProvenanceRouter::GetPendingRequestCount() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_pendingRequests.size();
}

size_t LSPProvenanceRouter::GetTotalRequestCount() const {
    return m_totalRequests.load();
}

size_t LSPProvenanceRouter::GetMatchedResponseCount() const {
    return m_matchedResponses.load();
}

size_t LSPProvenanceRouter::GetStaleResponseCount() const {
    return m_staleResponses.load();
}

size_t LSPProvenanceRouter::GetFallbackResponseCount() const {
    return m_fallbackResponses.load();
}

// ============================================================================
// Callbacks
// ============================================================================

void LSPProvenanceRouter::SetProvenanceCallback(ProvenanceCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_provenanceCallback = std::move(callback);
}

void LSPProvenanceRouter::SetValidationErrorCallback(ValidationErrorCallback callback) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_validationErrorCallback = std::move(callback);
}

// ============================================================================
// Cleanup
// ============================================================================

void LSPProvenanceRouter::CleanupStaleRequests() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto now = std::chrono::steady_clock::now();
    auto timeout = m_requestTimeout;
    
    for (auto it = m_pendingRequests.begin(); it != m_pendingRequests.end(); ) {
        auto age = std::chrono::duration_cast<std::chrono::milliseconds>(
            now - it->second.requestId.timestamp);
        
        if (age > timeout) {
            // Log timeout
            LogTimeout(it->first, it->second.requestId.method);
            it = m_pendingRequests.erase(it);
        } else {
            ++it;
        }
    }
}

void LSPProvenanceRouter::Reset() {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    m_pendingRequests.clear();
    m_currentFileVersions.clear();
    m_provenanceHistory.clear();
    m_totalRequests = 0;
    m_matchedResponses = 0;
    m_staleResponses = 0;
    m_fallbackResponses = 0;
}

// ============================================================================
// Private Methods
// ============================================================================

void LSPProvenanceRouter::EnforceMaxPendingRequests() {
    // Called with lock already held
    if (m_pendingRequests.size() >= m_maxPendingRequests) {
        // Remove oldest requests
        CleanupStaleRequests();
        
        // If still over limit, remove oldest
        while (m_pendingRequests.size() >= m_maxPendingRequests) {
            // Find oldest request
            uint64_t oldestId = 0;
            auto oldestTime = std::chrono::steady_clock::time_point::max();
            
            for (const auto& [id, context] : m_pendingRequests) {
                if (context.requestId.timestamp < oldestTime) {
                    oldestTime = context.requestId.timestamp;
                    oldestId = id;
                }
            }
            
            if (oldestId != 0) {
                LogTimeout(oldestId, m_pendingRequests[oldestId].requestId.method);
                m_pendingRequests.erase(oldestId);
            } else {
                break;
            }
        }
    }
}

void LSPProvenanceRouter::RecordProvenance(const LSPResponseProvenance& provenance) {
    // Called with lock already held
    
    m_provenanceHistory.push_back(provenance);
    
    // Enforce max history size
    if (m_provenanceHistory.size() > m_maxProvenanceHistory) {
        m_provenanceHistory.erase(m_provenanceHistory.begin());
    }
    
    // Invoke callback if set
    if (m_provenanceCallback) {
        m_provenanceCallback(provenance);
    }
}

// ============================================================================
// RAII Request Guard
// ============================================================================

LSPRequestGuard::LSPRequestGuard(const std::string& method)
    : m_method(method), m_valid(false) {
    
    m_requestId = LSPProvenanceRouter::Instance().GenerateRequestId(method);
    m_valid = true;
}

LSPRequestGuard::~LSPRequestGuard() {
    if (m_valid) {
        LSPProvenanceRouter::Instance().CompleteRequest(m_requestId);
    }
}

void LSPRequestGuard::BindFile(const std::string& uri, int version) {
    if (m_valid) {
        LSPProvenanceRouter::Instance().BindRequestToFile(m_requestId, uri, version);
    }
}

void LSPRequestGuard::BindCursor(int line, int character) {
    if (m_valid) {
        LSPProvenanceRouter::Instance().BindRequestToCursor(m_requestId, line, character);
    }
}

void LSPRequestGuard::BindLanguage(const std::string& languageId) {
    if (m_valid) {
        LSPProvenanceRouter::Instance().BindRequestToLanguage(m_requestId, languageId);
    }
}