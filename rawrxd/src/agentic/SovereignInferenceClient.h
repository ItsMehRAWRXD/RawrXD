// ============================================================================
// src/agentic/SovereignInferenceClient.h -- Sovereign inference client
// ============================================================================
// Declares RawrXD::Agent::SovereignInferenceClient. Its only definitions live in
// src/core/gold_link_closure.cpp.
//
// ----------------------------------------------------------------------------
// WHY THIS FILE EXISTS NOW (RAWRXD_MISSING_SOURCE_001)
// ----------------------------------------------------------------------------
// src/core/gold_link_closure.cpp:878 opens with this header, and that file is in
// the RawrXD_Gold source list:
//
//     src\core\gold_link_closure.cpp(878,10): error C1083: Cannot open include
//         file: 'agentic/SovereignInferenceClient.h': No such file or directory
//
// As with every other file in this series, the build-graph census counts it
// PRESENT: it scans CMakeLists.txt for declared SOURCES, and a missing #include
// is not a source-list entry. src/agentic/ exists and holds AgentOllamaClient
// and the cpp that implements it, so this header belongs beside them.
//
// ----------------------------------------------------------------------------
// SCOPE LIMIT -- READ BEFORE TRUSTING ANY BEHAVIOUR HERE
// ----------------------------------------------------------------------------
// Every definition in gold_link_closure.cpp is a link-closure stub, and the
// section comment above it says so: "SovereignInferenceClient (for
// agentic_deep_thinking_engine.cpp)". Measured, by reading the bodies:
//
//   LoadModel(gguf_path)  discards gguf_path, sets loaded = true, returns true.
//                         It reports SUCCESS for a path it never opened.
//   IsLoaded()            reports that flag, so it reports the same success.
//   ChatSync(...)         increments m_totalRequests and returns failure.
//   ChatStream(...)       invokes on_error and returns false.
//   ClearKVCache()        empty body.
//   GetAvgTokensPerSec()  returns 0.0 unconditionally.
//   UnloadModel()         clears the flag.
//
// Nothing here loads a model or runs inference. LoadModel returning true is the
// exact shape of false success that this repository's ledger treats as a failed
// gate, and it is recorded in the header so the next reader cannot mistake the
// declaration for a capability.
// ============================================================================

#pragma once

#include "../core/sovereign_gguf_loader.h"   // SovereignModelConfig (used by value)

#include "AgentOllamaClient.h"               // ChatMessage, InferenceResult

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <nlohmann/json_fwd.hpp>

namespace RawrXD {
namespace Agent {

// ============================================================================
// Streaming Callback Types
// ============================================================================
// TokenCallback and ToolCallCallback, and DoneCallback's parameterless shape,
// are pinned by nothing in the tree: gold_link_closure.cpp takes them as
// parameters, discards on_token / on_tool_call / on_done with (void), and calls
// ONLY on_error. So the four signatures below are the streaming analogue of the
// callback shapes that ARE pinned elsewhere -- unlinked_symbols_batch_018.cpp's
// ChatStream and FIMStream use
//     std::function<void(const std::string&)>                                  onToken
//     std::function<void(const std::string&, const nlohmann::json&)>           onToolCall
//     std::function<void(const std::string&, uint64_t, uint64_t, double)>      onProgress
//     std::function<void(const std::string&)>                                  onComplete
// and the declared type here differs only by omitting onProgress, which this
// interface does not take. ErrorCallback IS pinned: on_error is invoked with a
// bare string literal at gold_link_closure.cpp:920.
//
// Nothing in the tree currently constructs any of these, so a wrong parameter
// type would compile here and only fail at a future call site.
using TokenCallback     = std::function<void(const std::string& token)>;
using ToolCallCallback  = std::function<void(const std::string& name,
                                             const nlohmann::json& args)>;
using DoneCallback      = std::function<void()>;
using ErrorCallback     = std::function<void(const std::string& message)>;

// ============================================================================
// SovereignInferenceClient
// ============================================================================
class SovereignInferenceClient {
public:
    explicit SovereignInferenceClient(const SovereignModelConfig& cfg);
    ~SovereignInferenceClient();

    SovereignInferenceClient(const SovereignInferenceClient&)            = delete;
    SovereignInferenceClient& operator=(const SovereignInferenceClient&) = delete;

    // --- Model lifecycle ---
    // Both are stubs. LoadModel ignores gguf_path and reports success; see the
    // scope limit above.
    bool LoadModel(const std::string& gguf_path);
    void UnloadModel();
    bool IsLoaded() const;
    void ClearKVCache();

    // --- Inference ---
    InferenceResult ChatSync(const std::vector<ChatMessage>& messages,
                             const nlohmann::json& tools);

    bool ChatStream(const std::vector<ChatMessage>& messages,
                    const nlohmann::json& tools,
                    TokenCallback    on_token,
                    ToolCallCallback on_tool_call,
                    DoneCallback     on_done,
                    ErrorCallback    on_error);

    // Always 0.0 in the current implementation.
    double GetAvgTokensPerSec() const;

private:
    // Defined in the .cpp. Holds the loaded flag and a copy of the model config.
    class Impl;
    std::unique_ptr<Impl> pImpl_;

    SovereignModelConfig m_config;

    // Incremented by ChatSync only. Relaxed ordering because it is a pure
    // counter with no data it guards.
    std::atomic<uint64_t> m_totalRequests{0};
};

} // namespace Agent
} // namespace RawrXD