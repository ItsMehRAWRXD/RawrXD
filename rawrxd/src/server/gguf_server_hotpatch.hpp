// ============================================================================
// gguf_server_hotpatch.hpp — Server-Layer Hotpatching (Layer 3)
// Intercept HTTP API requests/responses for live model routing, guardrails,
// and A/B testing.  Runs inside the inference server (Win32IDE / Deep2).
//
// Design:
//   - No std::function (raw function pointer + optional context)
//   - Lock-free where possible; std::mutex for patch registry only
//   - C-compatible struct layout for potential ASM hooks
// Rule: NO SOURCE FILE IS TO BE SIMPLIFIED
// ============================================================================

#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdint>
#include <cstddef>
#include <vector>
#include <string>
#include <mutex>
#include <atomic>

namespace RawrXD {

// ============================================================================
// Request — Inference request intercepted by server hotpatch
// ============================================================================
struct Request {
    const char*     id;                 // Unique request ID
    const char*     model;              // Target model name (may be "auto")
    const char*     prompt;             // Raw prompt text
    uint32_t        maxTokens;
    float           temperature;
    float           topP;
    uint32_t        seed;
    bool            stream;             // Whether to stream tokens

    // Mutable params map for transforms to read/write
    struct ParamEntry {
        char        key[64];
        union {
            float   f;
            int     i;
            bool    b;
        } value;
        enum Type { Float, Int, Bool } type;
    };
    static constexpr size_t MAX_PARAMS = 32;
    ParamEntry params[MAX_PARAMS];
    size_t paramCount = 0;

    // Helpers for transform lambdas
    float* paramFloat(const char* key) {
        for (size_t i = 0; i < paramCount; ++i) {
            if (strcmp(params[i].key, key) == 0 && params[i].type == ParamEntry::Float) {
                return &params[i].value.f;
            }
        }
        return nullptr;
    }
};

// ============================================================================
// Response — Inference response intercepted by server hotpatch
// ============================================================================
struct Response {
    const char*     id;                 // Matches Request::id
    std::string     text;               // Generated text (mutable by transforms)
    uint32_t        tokens;             // Token count
    bool            done;               // Final chunk?
    double          tokensPerSec;       // Throughput metric
    uint32_t        errorCode;          // 0 = OK
};

// ============================================================================
// ServerHotpatch — Individual transform descriptor
// ============================================================================
struct ServerHotpatch {
    const char*     name;               // Patch name (stable pointer or strdup)
    uint64_t        hit_count;          // How many times invoked

    // Transform signature:
    //   req  = incoming request  (may be nullptr for post-response patches)
    //   resp = outgoing response (may be nullptr for pre-request patches)
    //   return true  = pass through to next layer / server
    //   return false = block / drop (response.text may contain error JSON)
    bool (*transform)(Request* req, Response* resp);

    // Optional predicate: only apply to requests matching this method/path
    const char*     method;             // e.g. "POST", "GET", or nullptr = any
    const char*     pattern;            // URL path substring, or nullptr = any

    // Priority ordering: lower = earlier in chain
    int32_t         priority;
    bool            enabled;

    ServerHotpatch()
        : name(nullptr), hit_count(0), transform(nullptr)
        , method(nullptr), pattern(nullptr), priority(0), enabled(true) {}
};

// ============================================================================
// GGUFServerHotpatch — Singleton registry for server-layer transforms
// ============================================================================
class GGUFServerHotpatch {
public:
    static GGUFServerHotpatch& instance();

    // Registry operations
    void add_patch(const ServerHotpatch& patch);
    bool removePatch(const char* name);
    size_t clearAllPatches();

    // Query
    std::vector<ServerHotpatch> getActivePatches() const;
    size_t getPatchCount() const;

    // Execution (called by HTTP server before/after inference)
    // Returns false if any transform blocks the request.
    bool runPreRequest(Request* req);
    bool runPostRequest(Request* req, Response* resp);
    bool runPreResponse(Response* resp);
    bool runPostResponse(Response* resp);
    bool runStreamChunk(Response* resp);

private:
    GGUFServerHotpatch() = default;
    ~GGUFServerHotpatch() = default;
    GGUFServerHotpatch(const GGUFServerHotpatch&) = delete;
    GGUFServerHotpatch& operator=(const GGUFServerHotpatch&) = delete;

    mutable std::mutex m_mtx;
    std::vector<ServerHotpatch> m_patches;
};

} // namespace RawrXD
