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
};

class AgentOrchestrator {
public:
    explicit AgentOrchestrator(std::uint32_t maxTurns = 16,
                               std::size_t contextCharBudget = 16000);

    // Binds the real inference engine. Required before SubmitAgenticTask.
    void SetInferenceStream(InferenceStreamFn fn);

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
    std::atomic<bool> running_{false};
    std::atomic<bool> stopFlag_{false};
    InferenceStreamFn inference_;
    mutable std::mutex diagMtx_;
    std::string diagnostics_;
};

} // namespace agentic
} // namespace rawrxd
