/**
 * FMF LSP Integration Header
 * 
 * LSP-specific fallback detection for the Failure Mode Firewall.
 * Instruments LSP client code paths to detect silent degradation.
 */

#pragma once

#include "FailureModeFirewall.h"
#include "FMF_FallbackMacros.h"

// ============================================================================
// LSP REAL EXECUTION MACROS
// ============================================================================

// Log real LSP execution (const char* method)
#define FMF_LSP_REAL_CALL(method) \
    FailureModeFirewall::Instance().ReportRealExecution(method, __FILE__, __FUNCTION__)

// Log LSP fallback execution (const char* reason)
#define FMF_LSP_FALLBACK_CALL(method, reason) \
    FailureModeFirewall::Instance().ReportFallback(reason, __FILE__, __LINE__)

// Log LSP timeout
#define FMF_LSP_REQUEST_TIMEOUT(method, timeoutMs) \
    do { \
        char _reason[256]; \
        snprintf(_reason, sizeof(_reason), "LSP_TIMEOUT_%s_%dms", method, timeoutMs); \
        FailureModeFirewall::Instance().ReportFallback(_reason, __FILE__, __LINE__); \
    } while(0)

// ============================================================================
// LSP CLIENT INITIALIZATION FALLBACKS
// ============================================================================

// LSP client not initialized
inline void FMF_LSP_NotInitialized() {
    FMF_FALLBACK("LSP_CLIENT_NOT_INITIALIZED");
}

// LSP server start failure
inline void FMF_LSP_ServerStartFailed(const char* serverName) {
    char reason[128];
    snprintf(reason, sizeof(reason), "LSP_SERVER_START_FAILED_%s", serverName);
    FMF_FALLBACK(reason);
}

// LSP pipe creation failure
inline void FMF_LSP_PipeCreationFailed() {
    FMF_FALLBACK("LSP_PIPE_CREATION_FAILED");
}

// LSP process creation failure
inline void FMF_LSP_ProcessCreationFailed(const char* executable) {
    char reason[256];
    snprintf(reason, sizeof(reason), "LSP_PROCESS_CREATION_FAILED_%s", executable);
    FMF_FALLBACK(reason);
}

// ============================================================================
// LSP REQUEST/RESPONSE FALLBACKS
// ============================================================================

// LSP request ID mismatch
inline void FMF_LSP_RequestIdMismatch(int expected, int actual) {
    char reason[128];
    snprintf(reason, sizeof(reason), "LSP_REQUEST_ID_MISMATCH_%d_%d", expected, actual);
    FMF_FALLBACK(reason);
}

// LSP response parsing failure
inline void FMF_LSP_ResponseParseError(const char* method) {
    char reason[256];
    snprintf(reason, sizeof(reason), "LSP_RESPONSE_PARSE_ERROR_%s", method);
    FMF_FALLBACK(reason);
}

// LSP timeout
inline void FMF_LSP_RequestTimeout(const char* method, int timeoutMs) {
    char reason[256];
    snprintf(reason, sizeof(reason), "LSP_TIMEOUT_%s_%dms", method, timeoutMs);
    FMF_FALLBACK(reason);
}

// LSP server crashed
inline void FMF_LSP_ServerCrashed(const char* serverName) {
    char reason[128];
    snprintf(reason, sizeof(reason), "LSP_SERVER_CRASHED_%s", serverName);
    FMF_FALLBACK(reason);
}

// ============================================================================
// LSP SEMANTIC FEATURES FALLBACKS
// ============================================================================

// LSP completion not available
inline void FMF_LSP_CompletionNotAvailable() {
    FMF_FALLBACK("LSP_COMPLETION_NOT_AVAILABLE");
}

// LSP hover not available
inline void FMF_LSP_HoverNotAvailable() {
    FMF_FALLBACK("LSP_HOVER_NOT_AVAILABLE");
}

// LSP references not available
inline void FMF_LSP_ReferencesNotAvailable() {
    FMF_FALLBACK("LSP_REFERENCES_NOT_AVAILABLE");
}

// LSP definition not available
inline void FMF_LSP_DefinitionNotAvailable() {
    FMF_FALLBACK("LSP_DEFINITION_NOT_AVAILABLE");
}

// LSP rename not available
inline void FMF_LSP_RenameNotAvailable() {
    FMF_FALLBACK("LSP_RENAME_NOT_AVAILABLE");
}

// LSP semantic tokens not available
inline void FMF_LSP_SemanticTokensNotAvailable() {
    FMF_FALLBACK("LSP_SEMANTIC_TOKENS_NOT_AVAILABLE");
}

// ============================================================================
// LSP BUFFER SYNCHRONIZATION FALLBACKS
// ============================================================================

// LSP file version mismatch
inline void FMF_LSP_VersionMismatch(int bufferVersion, int lspVersion) {
    char reason[128];
    snprintf(reason, sizeof(reason), "LSP_VERSION_MISMATCH_%d_%d", bufferVersion, lspVersion);
    FMF_FALLBACK(reason);
}

// LSP buffer not synchronized
inline void FMF_LSP_BufferNotSynced(const char* uri) {
    char reason[512];
    snprintf(reason, sizeof(reason), "LSP_BUFFER_NOT_SYNCED_%s", uri);
    FMF_FALLBACK(reason);
}

// LSP didOpen not sent
inline void FMF_LSP_DidOpenNotSent(const char* uri) {
    char reason[512];
    snprintf(reason, sizeof(reason), "LSP_DID_OPEN_NOT_SENT_%s", uri);
    FMF_FALLBACK(reason);
}

// ============================================================================
// LSP CONTENT LENGTH FRAMING FALLBACKS
// ============================================================================

// LSP content-length header missing
inline void FMF_LSP_ContentLengthMissing() {
    FMF_FALLBACK("LSP_CONTENT_LENGTH_MISSING");
}

// LSP content-length overflow
inline void FMF_LSP_ContentLengthOverflow(size_t length, size_t maxAllowed) {
    char reason[128];
    snprintf(reason, sizeof(reason), "LSP_CONTENT_LENGTH_OVERFLOW_%zu_%zu", length, maxAllowed);
    FMF_FALLBACK(reason);
}

// LSP message truncated
inline void FMF_LSP_MessageTruncated(size_t expected, size_t actual) {
    char reason[128];
    snprintf(reason, sizeof(reason), "LSP_MESSAGE_TRUNCATED_%zu_%zu", expected, actual);
    FMF_FALLBACK(reason);
}

// ============================================================================
// LSP JSON-RPC FALLBACKS
// ============================================================================

// LSP JSON parse error
inline void FMF_LSP_JsonParseError(const char* context) {
    char reason[256];
    snprintf(reason, sizeof(reason), "LSP_JSON_PARSE_ERROR_%s", context);
    FMF_FALLBACK(reason);
}

// LSP invalid method
inline void FMF_LSP_InvalidMethod(const char* method) {
    char reason[256];
    snprintf(reason, sizeof(reason), "LSP_INVALID_METHOD_%s", method);
    FMF_FALLBACK(reason);
}

// LSP invalid params
inline void FMF_LSP_InvalidParams(const char* method) {
    char reason[256];
    snprintf(reason, sizeof(reason), "LSP_INVALID_PARAMS_%s", method);
    FMF_FALLBACK(reason);
}

// ============================================================================
// LSP CAPABILITY FALLBACKS
// ============================================================================

// LSP capability not supported
inline void FMF_LSP_CapabilityNotSupported(const char* capability) {
    char reason[256];
    snprintf(reason, sizeof(reason), "LSP_CAPABILITY_NOT_SUPPORTED_%s", capability);
    FMF_FALLBACK(reason);
}

// LSP server capability mismatch
inline void FMF_LSP_CapabilityMismatch(const char* capability, bool clientHas, bool serverHas) {
    char reason[256];
    snprintf(reason, sizeof(reason), "LSP_CAPABILITY_MISMATCH_%s_%s_%s", 
             capability, clientHas ? "YES" : "NO", serverHas ? "YES" : "NO");
    FMF_FALLBACK(reason);
}

// ============================================================================
// LSP THREAD SAFETY FALLBACKS
// ============================================================================

// LSP reader thread error
inline void FMF_LSP_ReaderThreadError(const char* serverName) {
    char reason[128];
    snprintf(reason, sizeof(reason), "LSP_READER_THREAD_ERROR_%s", serverName);
    FMF_FALLBACK(reason);
}

// LSP write queue overflow
inline void FMF_LSP_WriteQueueOverflow() {
    FMF_FALLBACK("LSP_WRITE_QUEUE_OVERFLOW");
}

// LSP concurrent access violation
inline void FMF_LSP_ConcurrentAccessViolation() {
    FMF_FALLBACK("LSP_CONCURRENT_ACCESS_VIOLATION");
}

// ============================================================================
// LSP FALLBACK TRACKING MACROS
// ============================================================================

// Track LSP real execution
#define FMF_LSP_REAL_CALL(method) \
    FailureModeFirewall::Instance().ReportRealExecution("LSP_" method, __FILE__, __FUNCTION__)

// Track LSP fallback execution
#define FMF_LSP_FALLBACK_CALL(method, reason) \
    FMF_FALLBACK("LSP_" method "_" reason)

// ============================================================================
// LSP INTEGRITY CHECK MACROS
// ============================================================================

// Check if LSP is properly initialized before use
#define FMF_LSP_CHECK_INIT() \
    if (!m_lspInitialized) { \
        FMF_LSP_NotInitialized(); \
        return false; \
    }

// Check if LSP server is running
#define FMF_LSP_CHECK_SERVER(lang) \
    if (m_lspStatuses[(size_t)lang].state != LSPServerState::Running) { \
        FMF_LSP_ServerStartFailed(m_lspConfigs[(size_t)lang].name.c_str()); \
        return false; \
    }

// Check if LSP response is valid
#define FMF_LSP_CHECK_RESPONSE(response, method) \
    if (response.is_null() || response.contains("error")) { \
        FMF_LSP_ResponseParseError(method); \
        return false; \
    }