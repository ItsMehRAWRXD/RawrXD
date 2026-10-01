// ============================================================================
// AgentOrchestrator.cpp — RAWRXD_AGENTIC_ORCHESTRATOR_001
// ============================================================================
#include "agentic/AgentOrchestrator.h"

#include <windows.h>

#include <exception>
#include <sstream>
#include <utility>

namespace rawrxd {
namespace agentic {
namespace {

// GetTickCount64 has ~15.6 ms granularity, so it reports 0 for any turn that
// completes faster than one tick. QueryPerformanceCounter gives real
// microsecond resolution, which is what the latency field claims to be.
std::uint64_t NowMicros() {
    LARGE_INTEGER freq{};
    LARGE_INTEGER now{};
    if (!QueryPerformanceFrequency(&freq) || freq.QuadPart == 0) return 0;
    QueryPerformanceCounter(&now);
    return static_cast<std::uint64_t>((now.QuadPart * 1000000LL) / freq.QuadPart);
}

} // namespace

AgentOrchestrator::AgentOrchestrator(std::uint32_t maxTurns, std::size_t contextCharBudget)
    : state_(maxTurns, contextCharBudget) {}

void AgentOrchestrator::SetInferenceStream(InferenceStreamFn fn) {
    std::lock_guard<std::mutex> lk(diagMtx_);
    inference_ = std::move(fn);
}

void AgentOrchestrator::InitializeTools(const ToolPolicy& policy) {
    ToolRegistry& registry = ToolRegistry::Instance();
    registry.SetPolicy(policy);
    registry.InstallBuiltinTools();
}

void AgentOrchestrator::Stop() { stopFlag_.store(true, std::memory_order_release); }

std::string AgentOrchestrator::GetLastDiagnostics() const {
    std::lock_guard<std::mutex> lk(diagMtx_);
    return diagnostics_;
}

std::string AgentOrchestrator::BuildAssistantReplay(const std::string& text,
                                                    const ToolCallEvent& tool) const {
    // The real parameter values are replayed, not a literal "{params}" marker.
    // Without this the model sees a call it never made and the next turn drifts.
    std::ostringstream oss;
    oss << text;
    if (text.empty() || text.back() != '\n') oss << "\n";
    oss << "<<<TOOL:" << tool.name << "|" << tool.SerializeParamsJson() << ">>>\n";
    return oss.str();
}

TurnResult AgentOrchestrator::RunTurn(StreamCallback onStream, bool& fatal) {
    TurnResult result;
    fatal = false;

    InferenceStreamFn backend;
    {
        std::lock_guard<std::mutex> lk(diagMtx_);
        backend = inference_;
    }
    if (!backend) {
        result.outcome = TurnOutcome::FatalError;
        result.stopReason = "no inference backend bound (call SetInferenceStream)";
        fatal = true;
        return result;
    }

    const std::string prompt = state_.BuildContextWindow();
    result.promptTokens = EstimateTokens(prompt);
    result.turn = state_.CurrentTurn();

    parser_.Reset();
    std::string assistantText;
    ToolCallEvent tool;
    bool haveTool = false;
    std::string parserError;

    const std::uint64_t startMicros = NowMicros();
    bool backendOk = false;
    try {
        backendOk = backend(prompt, [&](const std::string& chunk) {
            if (stopFlag_.load(std::memory_order_acquire)) return;
            const FeedResult fed = parser_.Feed(chunk);
            if (!fed.text.empty()) {
                assistantText += fed.text;
                if (onStream) onStream(fed.text, false);
            }
            if (fed.toolComplete) {
                tool = parser_.PeekTool();
                haveTool = true;
            }
        });
        // Flush anything the parser withheld because it could have been a
        // delimiter prefix. Without this the last few characters of a reply are
        // silently lost.
        const std::string tail = parser_.Finish();
        if (!tail.empty()) {
            assistantText += tail;
            if (onStream) onStream(tail, false);
        }
    } catch (const std::exception& e) {
        result.outcome = TurnOutcome::FatalError;
        result.stopReason = std::string("inference backend threw: ") + e.what();
        result.latencyMicros = NowMicros() - startMicros;
        fatal = true;
        return result;
    } catch (...) {
        result.outcome = TurnOutcome::FatalError;
        result.stopReason = "inference backend threw a non-standard exception";
        result.latencyMicros = NowMicros() - startMicros;
        fatal = true;
        return result;
    }

    result.latencyMicros = NowMicros() - startMicros;
    result.completionTokens = EstimateTokens(assistantText);
    result.assistantText = assistantText;

    if (!backendOk) {
        result.outcome = TurnOutcome::FatalError;
        result.stopReason = "inference backend reported failure";
        fatal = true;
        return result;
    }

    if (parser_.MalformedBlockCount() > 0) {
        result.stopReason = "model emitted " +
                            std::to_string(parser_.MalformedBlockCount()) +
                            " malformed tool block(s)";
    }

    if (haveTool) {
        // Consume the pending tool so the next turn starts clean.
        tool = parser_.ExtractTool();
        result.outcome = TurnOutcome::ToolExecuted;
        result.toolName = tool.name;

        ToolRegistry& registry = ToolRegistry::Instance();
        const ToolResult toolResult = registry.Execute(tool.name, tool.params);
        result.toolSucceeded = toolResult.success;
        result.toolResult = toolResult.success ? toolResult.output : toolResult.error;

        if (onStream) {
            onStream("\n[tool " + tool.name + (toolResult.success ? "]\n" : " failed]\n"), true);
            onStream(result.toolResult + "\n", true);
        }

        // Record the assistant turn, then the tool result. Both are needed: the
        // assistant replay carries the call the model actually made.
        state_.PushAssistant(BuildAssistantReplay(assistantText, tool));
        state_.PushToolResult(tool.name, result.toolResult);
        return result;
    }

    // No tool call: this is the final answer.
    if (!assistantText.empty()) {
        state_.PushAssistant(assistantText);
    }
    result.outcome = TurnOutcome::Completed;
    if (result.stopReason.empty()) result.stopReason = "no_tool_call";
    return result;
}

AgentRunReport AgentOrchestrator::RunAgenticTask(const std::string& userPrompt,
                                                 StreamCallback onStream) {
    AgentRunReport report;
    running_.store(true, std::memory_order_release);
    stopFlag_.store(false, std::memory_order_release);
    parser_.Reset();

    const std::uint64_t startMicros = NowMicros();

    state_.Reset(ToolRegistry::Instance().BuildSystemPrompt());
    state_.PushUser(userPrompt);

    std::ostringstream diag;
    diag << "tools=" << ToolRegistry::Instance().Size()
         << " max_turns=" << state_.MaxTurns()
         << " initial_prompt_tokens=" << EstimateTokens(userPrompt) << "\n";

    for (;;) {
        if (stopFlag_.load(std::memory_order_acquire)) {
            report.error = "stopped by request";
            diag << "stop=requested\n";
            break;
        }
        if (!state_.ShouldContinue()) {
            report.error = state_.HasFatalError() ? state_.LastError()
                                                  : "max_turns_reached";
            diag << "stop=" << report.error << " turn=" << state_.CurrentTurn() << "\n";
            break;
        }

        bool fatal = false;
        const TurnResult turn = RunTurn(onStream, fatal);
        ++report.turnsExecuted;
        report.promptTokensTotal += turn.promptTokens;
        report.completionTokensTotal += turn.completionTokens;
        report.malformedToolBlocks += parser_.MalformedBlockCount();
        diag << "turn=" << turn.turn << " outcome=" << static_cast<int>(turn.outcome)
             << " prompt_tokens=" << turn.promptTokens
             << " completion_tokens=" << turn.completionTokens
             << " latency_us=" << turn.latencyMicros
             << " stop_reason=" << turn.stopReason << "\n";

        switch (turn.outcome) {
            case TurnOutcome::ToolExecuted: {
                ++report.toolCallsExecuted;
                if (!turn.toolSucceeded) {
                    ++report.toolCallsFailed;
                }
                break;
            }
            case TurnOutcome::Completed:
                report.success = true;
                report.finalText = turn.assistantText;
                break;
            case TurnOutcome::Stopped:
                report.error = "stopped";
                break;
            case TurnOutcome::MaxTurns:
                report.error = "max_turns_reached";
                break;
            case TurnOutcome::FatalError:
                report.error = turn.stopReason;
                state_.SetFatalError(turn.stopReason);
                break;
        }

        if (turn.outcome != TurnOutcome::ToolExecuted) break;
    }

    report.totalMicros = NowMicros() - startMicros;
    diag << "turns=" << report.turnsExecuted
         << " tools_executed=" << report.toolCallsExecuted
         << " tools_failed=" << report.toolCallsFailed
         << " malformed_blocks=" << report.malformedToolBlocks
         << " prompt_tokens_total=" << report.promptTokensTotal
         << " completion_tokens_total=" << report.completionTokensTotal
         << " total_us=" << report.totalMicros
         << " success=" << (report.success ? 1 : 0) << "\n";

    {
        std::lock_guard<std::mutex> lk(diagMtx_);
        diagnostics_ = diag.str();
    }
    running_.store(false, std::memory_order_release);
    return report;
}

std::future<AgentRunReport> AgentOrchestrator::SubmitAgenticTask(const std::string& userPrompt,
                                                                 StreamCallback onStream) {
    return std::async(std::launch::async,
                      [this, userPrompt, onStream]() {
                          return RunAgenticTask(userPrompt, onStream);
                      });
}

} // namespace agentic
} // namespace rawrxd
