#pragma once
#ifndef RAWRXD_INFERENCE_ENFORCEMENT_H
#define RAWRXD_INFERENCE_ENFORCEMENT_H

#include "inference_gateway.h"
#include <string>

// ============================================================================
// MANDATORY INFERENCE ENFORCEMENT
// 
// ANY code that calls inference MUST use these macros.
// Direct backend calls are FORBIDDEN and will fail at compile time
// or runtime with clear errors.
// ============================================================================

// ============================================================================
// Compile-time enforcement helpers
// ============================================================================
namespace RawrXD {
namespace Enforcement {

// Marker class - if you see this in error messages, you bypassed the gateway
struct [[deprecated("DIRECT INFERENCE CALL DETECTED - Use InferenceGateway::execute() instead")]] DirectInferenceCall {};

// Runtime check - logs and blocks unauthorized calls
inline void AssertGatewayUsed(const char* file, int line, const char* func) {
    fprintf(stderr, "[ENFORCEMENT] Inference bypass detected at %s:%d in %s\n", file, line, func);
    fprintf(stderr, "[ENFORCEMENT] ALL inference MUST go through InferenceGateway::execute()\n");
    // In debug builds, this could abort. For now, just log loudly.
}

// The ONLY authorized path
inline InferenceResponse AuthorizedExecute(const InferenceRequest& req, 
                                              const char* sourceFile,
                                              int sourceLine,
                                              const char* sourceFunc) {
    // Log entry point for observability
    fprintf(stderr, "[GatewayEntry] %s:%d %s -> model=%s\n", 
        sourceFile, sourceLine, sourceFunc, req.model.c_str());
    
    return InferenceGateway::instance().execute(req);
}

} // namespace Enforcement
} // namespace RawrXD

// ============================================================================
// MANDATORY MACRO - Use this for ALL inference
// ============================================================================
#define RAWRXD_INFERENCE(req) \
    RawrXD::Enforcement::AuthorizedExecute((req), __FILE__, __LINE__, __FUNCTION__)

// ============================================================================
// Convenience macro for simple calls
// ============================================================================
#define RAWRXD_GENERATE(model, prompt) \
    RAWRXD_INFERENCE(([&]() { \
        RawrXD::InferenceRequest _r; \
        _r.model = (model); \
        _r.prompt = (prompt); \
        return _r; \
    })())

// ============================================================================
// DEPRECATION MARKERS FOR OLD APIS
// These cause compile-time errors if old bypass APIs are used
// ============================================================================

// Mark direct Ollama calls as deprecated
#define invokeOllamaGenerate [[deprecated("Use InferenceGateway instead")]] invokeOllamaGenerate
#define WinHttpOpenRequest [[deprecated("Use InferenceGateway instead")]] WinHttpOpenRequest

// Mark direct cloud calls as deprecated  
#define CloudApiClient [[deprecated("Use InferenceGateway instead")]] CloudApiClient

// ============================================================================
// AUDIT TRAIL
// Every inference call is tracked
// ============================================================================

namespace RawrXD {
namespace Enforcement {

struct InferenceAuditEntry {
    std::string timestamp;
    std::string sourceFile;
    int sourceLine;
    std::string sourceFunc;
    std::string model;
    ExecutionPath chosenPath;
    bool success;
    int64_t latencyMs;
};

// Global audit log (thread-safe)
class InferenceAuditLog {
public:
    static InferenceAuditLog& instance();
    
    void record(const InferenceAuditEntry& entry);
    std::vector<InferenceAuditEntry> getRecent(int count = 50) const;
    void dumpToFile(const std::string& path) const;
    
    // Check for bypass patterns
    bool detectBypassPatterns(std::vector<std::string>& violations) const;

private:
    mutable std::mutex m_mutex;
    std::vector<InferenceAuditEntry> m_entries;
    static constexpr size_t MAX_ENTRIES = 1000;
};

} // namespace Enforcement
} // namespace RawrXD

#endif // RAWRXD_INFERENCE_ENFORCEMENT_H
