# LSP Provenance Router - Implementation Summary

## Overview

The LSP Provenance Router provides per-request lineage tracing for LSP operations, resolving the critical issue of "silent semantic degradation without runtime visibility."

## Architecture

### Three Execution Planes

| Plane | Role | What it tracks |
|-------|------|----------------|
| **Feature code** | What *should* happen | Intended behavior |
| **Stub layer** | What *pretends* to happen | Fallback paths |
| **FMF layer** | What *actually happened* | Real execution |

### Key Components

1. **Request ID Propagation**
   - Every LSP request gets: `request_id`, `file_version`, `cursor_position`
   - Response binding validation rejects mismatches

2. **Response Provenance Tagging**
   - Tag each response with: `request_id`, `timestamp`, `execution_path`
   - FMF hooks log: LSP real response, LSP fallback response, LSP timeout fallback

3. **Version Synchronization**
   - Track file versions between editor buffer and LSP
   - Reject stale responses

## Files Created

| File | Purpose |
|------|---------|
| `include/lsp_provenance_router.h` | Header with request tracking structures |
| `src/lsp/lsp_provenance_router.cpp` | Implementation with FMF integration |

## Key Classes

### LSPRequestId
```cpp
struct LSPRequestId {
    uint64_t id;
    std::string method;
    std::chrono::steady_clock::time_point timestamp;
};
```

### LSPRequestContext
```cpp
struct LSPRequestContext {
    LSPRequestId requestId;
    LSPFileVersion fileVersion;
    LSPCursorPosition cursorPosition;
    std::string languageId;
    bool isValid;
    std::string validationError;
};
```

### LSPResponseProvenance
```cpp
struct LSPResponseProvenance {
    uint64_t requestId;
    std::string method;
    std::chrono::milliseconds latency;
    bool matched;
    bool stale;
    bool fallback;
    std::string executionPath; // "real" or "stub" or "fallback"
};
```

### LSPProvenanceRouter
```cpp
class LSPProvenanceRouter {
    // Request ID management
    uint64_t GenerateRequestId(const std::string& method);
    bool BindRequestToFile(uint64_t requestId, const std::string& uri, int version);
    
    // Response validation
    bool ValidateResponse(uint64_t requestId, const nlohmann::json& response);
    bool CheckFileVersion(uint64_t requestId, int currentVersion);
    
    // FMF integration
    void LogRealExecution(uint64_t requestId, const std::string& method);
    void LogFallbackExecution(uint64_t requestId, const std::string& method, const std::string& reason);
    void LogTimeout(uint64_t requestId, const std::string& method);
};
```

## Usage Examples

### Basic Request Tracking
```cpp
// Start tracking
LSP_PROVENANCE_START("textDocument/completion");

// Bind context
_lsp_guard.BindFile("file:///path/to/file.cpp", 42);
_lsp_guard.BindCursor(10, 5);

// ... make LSP request ...

// Validate response
if (!LSP_PROVENANCE_VALIDATE(response)) {
    LSP_PROVENANCE_FALLBACK("textDocument/completion", "VALIDATION_FAILED");
    return;
}

// End tracking
LSP_PROVENANCE_END("textDocument/completion");
```

### RAII Guard Pattern
```cpp
{
    LSPRequestGuard guard("textDocument/hover");
    guard.BindFile(uri, version);
    guard.BindCursor(line, character);
    
    // ... make LSP request ...
    
    // Automatic cleanup on scope exit
}
```

### FMF Integration
```cpp
// Real execution
LSPProvenanceRouter::Instance().LogRealExecution(requestId, "textDocument/definition");

// Fallback execution
LSPProvenanceRouter::Instance().LogFallbackExecution(requestId, "textDocument/definition", "LSP_CLIENT_NULL");

// Timeout
LSPProvenanceRouter::Instance().LogTimeout(requestId, "textDocument/completion");
```

## Validation Rules

### Request ID Mismatch
```cpp
if (responseId != requestId) {
    FMF_LSP_RequestIdMismatch(requestId, responseId);
    return false;
}
```

### File Version Mismatch
```cpp
if (currentVersion != requestVersion) {
    FMF_LSP_VersionMismatch(requestVersion, currentVersion);
    return false;
}
```

### Error Response
```cpp
if (response.contains("error")) {
    FMF_LSP_ResponseParseError(method);
    return false;
}
```

## Statistics

```cpp
size_t pending = LSPProvenanceRouter::Instance().GetPendingRequestCount();
size_t total = LSPProvenanceRouter::Instance().GetTotalRequestCount();
size_t matched = LSPProvenanceRouter::Instance().GetMatchedResponseCount();
size_t stale = LSPProvenanceRouter::Instance().GetStaleResponseCount();
size_t fallback = LSPProvenanceRouter::Instance().GetFallbackResponseCount();
```

## Integration with FMF

The LSP Provenance Router integrates with the Failure Mode Firewall through:

1. **Real Execution Logging**
   - `FMF_LSP_REAL_CALL(method)` - Track real LSP execution

2. **Fallback Detection**
   - `FMF_LSP_FALLBACK_CALL(method, reason)` - Track fallback paths
   - `FMF_LSP_CLIENT_NULL()` - LSP client not available
   - `FMF_LSP_TIMEOUT(method, timeoutMs)` - LSP timeout

3. **Validation Errors**
   - `FMF_LSP_RequestIdMismatch(expected, actual)` - Request ID mismatch
   - `FMF_LSP_VersionMismatch(bufferVersion, lspVersion)` - File version mismatch
   - `FMF_LSP_ResponseParseError(method)` - Response parsing failure

## Benefits

1. **Request Lineage Tracing** - Every LSP request has a complete audit trail
2. **Response Validation** - Automatic rejection of stale/mismatched responses
3. **FMF Integration** - All LSP fallbacks are logged to the Failure Mode Firewall
4. **Statistics** - Real-time metrics on LSP health
5. **Debugging** - Clear provenance for every LSP response

## Next Steps

1. **Integrate into Win32IDE_LSPClient.cpp** - Add provenance tracking to all LSP methods
2. **Add to CMakeLists.txt** - Build the provenance router
3. **Create LSP smoke test** - Test provenance tracking with real LSP operations
4. **Add provenance dashboard** - Visualize LSP request/response lineage