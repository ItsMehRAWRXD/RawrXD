// ============================================================================
// AgentOrchestrator.h — RAWRXD_AGENTIC_ORCHESTRATOR_001
// The full tool-calling REPL: prompt -> model -> tool call -> execute -> repeat.
//
// The model backend is injected. There is deliberately no default backend that
// fabricates text: with no backend bound, SubmitAgenticTask fails loudly rather
// than simulating a conversation.
// ============================================================================
#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "agentic/AgentStateManager.h"
#include "agentic/AgentToolRegistry.h"
#include "agentic/ModelToolProtocol.h"
#include "agentic/StreamingToolParser.h"

namespace rawrxd {
namespace agentic {

// One streamed chunk. `done` is true on the final call.
struct StreamChunk {
    std::string text;
    bool done = false;
};

// Stream sink type used by the backend.
using StreamCallbackBase = std::function<void(const std::string&)>;

// Injected model backend. Must emit chunks in order and set done on the last
// one. Returning false means the backend failed. Throwing is caught by the
// caller and surfaced as a turn failure.
using InferenceStreamFn =
    std::function<bool(const std::string& prompt, const StreamCallbackBase& emit)>;

enum class TurnOutcome {
    Completed,       // model produced a final answer with no tool call
    ToolExecuted,    // a tool ran; the loop continues
    Stopped,         // Stop() was called
    MaxTurns,        // turn budget exhausted
    FatalError,      // backend or tool failure the loop cannot recover from
};

struct TurnResult {
    TurnOutcome outcome = TurnOutcome::FatalError;
    std::string assistantText;
    std::string toolName;
    std::string toolResult;
    bool toolSucceeded = false;
    std::string stopReason;
    std::uint32_t turn = 0;
    std::uint32_t promptTokens = 0;
    std::uint32_t completionTokens = 0;
    std::uint64_t latencyMicros = 0;

    // RAWRXD_MODEL_TOOL_PROTOCOL_AUTHORITY_001
    //
    // Which tier produced this call, and who actually decided it. A caller that
    // cannot tell native tool calling from runtime-inferred intent cannot report
    // the agent's capability honestly, so the distinction is carried on the
    // result rather than logged and forgotten.
    mtproto::Dialect toolDialect = mtproto::Dialect::None;
    mtproto::Agency toolAgency = mtproto::Agency::RuntimeInferred;
};

// Receives text and tool activity. `isToolResult` distinguishes user-visible
// assistant text from tool output.
using StreamCallback = std::function<void(const std::string& text, bool isToolResult)>;

// Measured outcome of a whole agentic task.
struct AgentRunReport {
    bool success = false;
    std::uint32_t turnsExecuted = 0;
    std::uint32_t toolCallsExecuted = 0;
    std::uint32_t toolCallsFailed = 0;
    std::uint32_t malformedToolBlocks = 0;
    std::uint32_t promptTokensTotal = 0;
    std::uint32_t completionTokensTotal = 0;
    std::uint64_t totalMicros = 0;
    std::string finalText;
    std::string error;

    // Agency breakdown, so a report cannot imply more model capability than
    // the model has.
    std::uint32_t toolCallsNative = 0;
    std::uint32_t toolCallsUnmarked = 0;
    std::uint32_t toolCallsInferred = 0;
    mtproto::Tier protocolTier = mtproto::Tier::Unsupported;
    mtproto::NativeSupport nativeSupport = mtproto::NativeSupport::Undeclared;
    std::string tierReason;

    // RAWRXD_MODEL_TOOL_PROTOCOL_AUTHORITY_001
    //
    // How much of the last tool observation the context budget forced out. Zero
    // means the model saw the whole result. Non-zero means it saw the tool's
    // name and status and part of its output, and a report that says "the tool
    // ran and the loop finished" without this number is claiming more than
    // happened.
    std::uint32_t observationTruncatedChars = 0;
    std::uint32_t contextMessagesDropped = 0;
};

class AgentOrchestrator {
public:
    explicit AgentOrchestrator(std::uint32_t maxTurns = 16,
                               std::size_t contextCharBudget = 16000);

    // Binds the real inference engine. Required before SubmitAgenticTask.
    void SetInferenceStream(InferenceStreamFn fn);

    // RAWRXD_MODEL_TOOL_PROTOCOL_AUTHORITY_001
    //
    // Declares which model is behind `inference_`. Without this the loop runs
    // the puppeteer tier, which is the correct default for an unknown model and
    // the reason a model with no tool-calling training can still finish a task.
    // `support` is the result of a live probe, not a claim: pass
    // NativeSupport::Undeclared until one has actually run.
    void SetModelProfile(const mtproto::ModelIdentity& id,
                         mtproto::NativeSupport support);
    const mtproto::ModelIdentity& ModelProfile() const { return modelId_; }
    mtproto::NativeSupport NativeSupportLevel() const { return nativeSupport_; }
    mtproto::Negotiation Protocol() const;

    // RAWRXD_MODEL_TOOL_PROTOCOL_AUTHORITY_001 -- the adoption point.
    //
    // Runs BuildNativeProbePrompt through the bound backend and records what the
    // model ACTUALLY emitted. Without this, ProbeNativeToolCalling is an
    // unreferenced function and NATIVE_TOOL_CALLING can only ever be
    // UNDECLARED -- an authority nobody calls is not a capability.
    //
    // Returns false when no backend is bound or a task is already running; in
    // both cases nativeSupport_ is left untouched rather than guessed.
    //
    // Measured against real weights on 2026-10-02:
    //   tinyllama-1.1b-chat-v1.0.Q4_K_M -> UNSUPPORTED, and it does not follow
    //     the puppeteer form either, so no tier reaches it
    //   llama3.2-3b-Q2_K                -> UNSUPPORTED (no trained marker) but
    //     it DOES emit a parseable call, and the puppeteer tier executes it
    bool ProbeNativeSupport(const std::string& toolName = "read_file",
                            const std::string& argName = "path",
                            const std::string& argValue = "AGENTS.md");

    // The exact text the model returned to the probe. Kept verbatim so the
    // verdict can be audited against the evidence rather than trusted.
    std::string LastNativeProbeReply() const;
    mtproto::Dialect LastNativeProbeDialect() const;

    // Registers the built-in tools and installs the given policy.
    void InitializeTools(const ToolPolicy& policy);

    AgentStateManager& State() { return state_; }
    ToolRegistry& Tools() { return ToolRegistry::Instance(); }

    // Runs the REPL on a worker thread. The future carries the measured report.
    std::future<AgentRunReport> SubmitAgenticTask(const std::string& userPrompt,
                                                  StreamCallback onStream);

    // Synchronous variant for callers already on a worker thread.
    AgentRunReport RunAgenticTask(const std::string& userPrompt, StreamCallback onStream);

    void Stop();
    bool IsRunning() const { return running_.load(std::memory_order_acquire); }

    // Measured diagnostic string from the most recent run.
    std::string GetLastDiagnostics() const;

private:
    TurnResult RunTurn(StreamCallback onStream, bool& fatal);
    std::string BuildAssistantReplay(const std::string& text, const ToolCallEvent& tool) const;

    AgentStateManager state_;
    StreamingToolParser parser_;
    mtproto::ModelIdentity modelId_;
    mtproto::NativeSupport nativeSupport_ = mtproto::NativeSupport::Undeclared;
    mutable std::string nativeProbeReply_;
    mtproto::Dialect nativeProbeDialect_ = mtproto::Dialect::None;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopFlag_{false};
    InferenceStreamFn inference_;
    mutable std::mutex diagMtx_;
    std::string diagnostics_;
};

} // namespace agentic
} // namespace rawrxd
