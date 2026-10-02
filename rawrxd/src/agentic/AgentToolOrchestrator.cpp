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

// RAWRXD_MODEL_TOOL_PROTOCOL_AUTHORITY_001
void AgentOrchestrator::SetModelProfile(const mtproto::ModelIdentity& id,
                                        mtproto::NativeSupport support) {
    modelId_ = id;
    nativeSupport_ = support;
}

mtproto::Negotiation AgentOrchestrator::Protocol() const {
    return mtproto::ProtocolAuthority::Instance().Negotiate(modelId_, nativeSupport_);
}

// RAWRXD_MODEL_TOOL_PROTOCOL_AUTHORITY_001 -- the adoption point.
bool AgentOrchestrator::ProbeNativeSupport(const std::string& toolName,
                                          const std::string& argName,
                                          const std::string& argValue) {
    InferenceStreamFn backend;
    {
        std::lock_guard<std::mutex> lk(diagMtx_);
        backend = inference_;
    }
    // No backend and no verdict. Guessing here is exactly the failure this
    // function exists to remove.
    if (!backend) return false;
    if (running_.load(std::memory_order_acquire)) return false;

    const std::string prompt =
        mtproto::ProtocolAuthority::BuildNativeProbePrompt(toolName, argName, argValue);

    std::string reply;
    bool ok = false;
    try {
        ok = backend(prompt, [&reply](const std::string& chunk) { reply += chunk; });
    } catch (...) {
        // A backend that throws has told us nothing about the model. Leave
        // nativeSupport_ alone: an exception is not a measurement.
        return false;
    }
    if (!ok) return false;

    mtproto::Dialect dialect = mtproto::Dialect::None;
    const mtproto::NativeSupport observed =
        mtproto::ProtocolAuthority::ProbeNativeToolCalling(reply, &dialect);

    nativeSupport_ = observed;
    nativeProbeDialect_ = dialect;
    {
        std::lock_guard<std::mutex> lk(diagMtx_);
        nativeProbeReply_ = reply;
        diagnostics_ = "native_probe: support=" +
                       std::string(mtproto::ToString(observed)) + " dialect=" +
                       mtproto::ToString(dialect) + " reply_bytes=" +
                       std::to_string(reply.size());
    }
    return true;
}

std::string AgentOrchestrator::LastNativeProbeReply() const {
    std::lock_guard<std::mutex> lk(diagMtx_);
    return nativeProbeReply_;
}

mtproto::Dialect AgentOrchestrator::LastNativeProbeDialect() const {
    return nativeProbeDialect_;
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
        // The streaming path is the Rawr dialect, which RawrXD taught. That is
        // a convention, not the model's own training, and the report says so.
        result.toolDialect = mtproto::Dialect::RawrToolBlock;
        result.toolAgency = mtproto::Agency::ModelUnmarked;

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

    // RAWRXD_MODEL_TOOL_PROTOCOL_AUTHORITY_001
    //
    // The streaming parser only knows one dialect, so a model that emits a
    // native marker, a ReAct action, or a plain call-shaped line reaches here
    // with no tool call at all and used to be treated as having answered. Every
    // other protocol the runtime can serve is resolved from the finished text.
    {
        mtproto::ProtocolAuthority& auth = mtproto::ProtocolAuthority::Instance();
        const mtproto::Negotiation negotiation = auth.Negotiate(modelId_, nativeSupport_);
        ToolRegistry& registry = ToolRegistry::Instance();
        const mtproto::ExtractResult ex =
            auth.Extract(negotiation, modelId_, assistantText, registry.GetDefs());

        if (!ex.accepted.empty()) {
            // Only the first accepted call runs. A model that emitted several is
            // not run all at once: an unproven model plus an unproven multi-call
            // is how a hallucinated tool chain becomes a real one.
            const mtproto::Intent& it = ex.accepted.front();
            result.outcome = TurnOutcome::ToolExecuted;
            result.toolName = it.name;
            result.toolDialect = it.dialect;
            result.toolAgency = it.agency;

            const ToolResult toolResult = registry.Execute(it.name, it.args);
            result.toolSucceeded = toolResult.success;
            result.toolResult = toolResult.success ? toolResult.output : toolResult.error;

            if (onStream) {
                onStream("\n[tool " + it.name + (toolResult.success ? "]\n" : " failed]\n"), true);
                onStream(result.toolResult + "\n", true);
            }

            // The observation is dressed for the dialect the model actually
            // used. A Hermes-trained model is shown <tool_response>; a
            // puppeteered model is shown plain text.
            std::string argsJson;
            for (const auto& kv : it.args) {
                if (!argsJson.empty()) argsJson += ",";
                argsJson += "\"" + kv.first + "\":\"" + kv.second + "\"";
            }
            const std::string observation = mtproto::ProtocolAuthority::BuildObservation(
                it.name, argsJson, toolResult.success, result.toolResult, it.dialect);

            // Replay what the model actually said. Unlike the Rawr path there is
            // no marker to reconstruct, because the model never wrote one.
            state_.PushAssistant(assistantText.empty() ? std::string() : assistantText);
            state_.PushToolResult(it.name, observation);
            return result;
        }
    }

    // No tool call in any protocol: this is the final answer.
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
    // RAWRXD_MODEL_TOOL_PROTOCOL_AUTHORITY_001
    //
    // The prompt is chosen by the tier, not fixed. A model the probe confirmed
    // is native gets NO grammar, because re-teaching a model its own protocol
    // is how it starts emitting the wrong marker. Everything else is told the
    // one convention the runtime can actually parse out of its text.
    mtproto::ProtocolAuthority& auth = mtproto::ProtocolAuthority::Instance();
    const mtproto::Negotiation negotiation = auth.Negotiate(modelId_, nativeSupport_);
    const ToolRegistry& registry = ToolRegistry::Instance();
    const std::vector<ToolDef> defs = registry.GetDefs();
    const mtproto::ModelHotpatch* hp = nullptr;
    {
        // Resolve the hotpatch for the notes line without duplicating the
        // lookup rule: negotiate again against a one-element view is not an
        // option, so the hotpatch id is taken from the negotiation itself.
        if (negotiation.hotpatchApplied) {
            for (const mtproto::ModelHotpatch& cand : auth.Hotpatches()) {
                if (cand.id == negotiation.hotpatchId) { hp = &cand; break; }
            }
        }
    }

    state_.Reset(mtproto::ProtocolAuthority::BuildToolInstructions(defs, negotiation, hp));
    state_.PushUser(userPrompt);

    report.protocolTier = negotiation.tier;
    report.nativeSupport = negotiation.nativeSupport;
    report.tierReason = negotiation.reason;

    std::ostringstream diag;
    diag << "tools=" << ToolRegistry::Instance().Size()
         << " tier=" << mtproto::ToString(negotiation.tier)
         << " native=" << mtproto::ToString(negotiation.nativeSupport)
         << " hotpatch=" << (negotiation.hotpatchId.empty() ? "none" : negotiation.hotpatchId)
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
             << " tool=" << (turn.toolName.empty() ? "-" : turn.toolName)
             << " dialect=" << mtproto::ToString(turn.toolDialect)
             << " agency=" << mtproto::ToString(turn.toolAgency)
             << " stop_reason=" << turn.stopReason << "\n";

        switch (turn.outcome) {
            case TurnOutcome::ToolExecuted: {
                ++report.toolCallsExecuted;
                if (!turn.toolSucceeded) {
                    ++report.toolCallsFailed;
                }
                // Agency is counted separately from success. A run that only
                // worked because RawrXD inferred the call is not evidence that
                // the model can call tools, and the report has to say which it
                // was.
                switch (turn.toolAgency) {
                    case mtproto::Agency::ModelNative:     ++report.toolCallsNative; break;
                    case mtproto::Agency::ModelUnmarked:   ++report.toolCallsUnmarked; break;
                    case mtproto::Agency::RuntimeInferred: ++report.toolCallsInferred; break;
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

    // The context window is rebuilt at the start of every turn, so the last
    // build reflects the final state. Both numbers are the cost of the budget,
    // and both are reported because a run that dropped the observation and
    // still says "success" has not told the truth about what the model saw.
    report.observationTruncatedChars = state_.LastTruncatedCharCount();
    report.contextMessagesDropped = state_.LastDroppedMessageCount();

    report.totalMicros = NowMicros() - startMicros;
    diag << "turns=" << report.turnsExecuted
         << " tools_executed=" << report.toolCallsExecuted
         << " tools_failed=" << report.toolCallsFailed
         << " tools_native=" << report.toolCallsNative
         << " tools_unmarked=" << report.toolCallsUnmarked
         << " tools_inferred=" << report.toolCallsInferred
         << " malformed_blocks=" << report.malformedToolBlocks
         << " prompt_tokens_total=" << report.promptTokensTotal
         << " completion_tokens_total=" << report.completionTokensTotal
         << " observation_truncated_chars=" << report.observationTruncatedChars
         << " context_messages_dropped=" << report.contextMessagesDropped
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
