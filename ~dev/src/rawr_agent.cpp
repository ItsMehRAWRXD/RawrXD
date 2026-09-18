// ============================================================================
// rawr_agent.cpp — RAWR_AGENT_LOOP_001 + RAWR_AUDIT_COVERAGE_001 implementation.
// The one unified loop: model -> tool call -> tool result -> model -> ...
// -> final. Bounded steps. Hard failure semantics. Runtime-owned completion
// authority via the audit ledger. Chat framing uses the Qwen2.5 template;
// the stop condition is the literal <|im_end|> token (tokenizer preserves
// specials literally, engine lacks EOS metadata — we stop in the callback).
// ============================================================================
#include "rawr_agent.hpp"

#include <cstdio>
#include <filesystem>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

#include "deep2/AgentToolAuthority.hpp"
#include "deep2/AgentToolRegistry.hpp"
#include "rawr_agent_dispatch.hpp"
#include "rawr_run_stream.hpp"

namespace rawrxd {
namespace agent {

using RawrXD::Agentic::AgentToolRegistry;
using RawrXD::Agentic::AgentToolSurface;
using RawrXD::Agentic::BindAgentToolAuthority;
using RawrXD::Agentic::ToolRequest;
using RawrXD::Agentic::ToolResult;
using rawrxd::runstream::RawrDeep2Runner;
using rawrxd::runstream::RunStreamReceipt;

namespace {

// ---------------------------------------------------------------------------
// Reply protocol — <tool>/<args> tags, consistent with the established
// headless convention. Final replies carry no tool tag.
// ---------------------------------------------------------------------------
struct ModelReply {
    enum class Kind { ToolCall, Final, ProtocolError } kind = Kind::ProtocolError;
    std::string tool;
    std::string args;      // JSON object string
    std::string text;      // final text or raw on error
};

std::string between(const std::string& s, const std::string& open,
                    const std::string& close) {
    const size_t a = s.find(open);
    if (a == std::string::npos) return {};
    const size_t b = s.find(close, a + open.size());
    if (b == std::string::npos) return {};
    return s.substr(a + open.size(), b - a - open.size());
}

std::string trim(std::string s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return {};
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

// Strip markdown code fences that models habitually wrap around replies.
std::string stripFences(std::string s) {
    auto eraseAll = [&](const std::string& t) {
        size_t p;
        while ((p = s.find(t)) != std::string::npos) s.erase(p, t.size());
    };
    eraseAll("```");
    return s;
}

// Known tool names (filled at registration time by setKnownToolNames).
std::vector<std::string>& knownTools() {
    static std::vector<std::string> names;
    return names;
}

bool isKnownTool(const std::string& name) {
    for (const auto& n : knownTools())
        if (n == name) return true;
    return false;
}

ModelReply parseReply(const std::string& raw) {
    ModelReply r;
    const std::string cleaned = stripFences(raw);
    const std::string tool = between(cleaned, "<tool>", "</tool>");
    if (!tool.empty()) {
        r.kind = ModelReply::Kind::ToolCall;
        r.tool = trim(tool);
        r.args = between(cleaned, "<args>", "</args>");
        if (r.args.empty()) r.args = "{}";
        return r;
    }
    // A bare <args> block with no tool is a protocol error.
    if (cleaned.find("<args>") != std::string::npos) {
        r.kind = ModelReply::Kind::ProtocolError;
        r.text = raw;
        return r;
    }
    // Lenient parse: first line is exactly "tool.name {json}" where the name
    // is a registered tool. Models sometimes emit the call bare (observed in
    // the first smoke run); accept it rather than losing the turn.
    {
        std::istringstream lines(cleaned);
        std::string first;
        if (std::getline(lines, first)) {
            first = trim(first);
            const size_t brace = first.find('{');
            if (brace != std::string::npos && brace > 0) {
                const std::string candidate = trim(first.substr(0, brace));
                const std::string jsonPart = trim(first.substr(brace));
                const size_t close = jsonPart.rfind('}');
                const bool validJson = close != std::string::npos;
                if (isKnownTool(candidate) && validJson) {
                    r.kind = ModelReply::Kind::ToolCall;
                    r.tool = candidate;
                    r.args = jsonPart;
                    return r;
                }
            }
        }
    }
    r.kind = ModelReply::Kind::Final;
    r.text = raw;
    return r;
}

// ---------------------------------------------------------------------------
// Chat assembly — Qwen2.5 chat template. Context compaction: each step feeds
// only (system + original request + recent N tool transactions + instruction).
// ---------------------------------------------------------------------------
constexpr size_t kMaxHistoryEntries = 6;   // tool transactions kept per step

struct ToolTransaction {
    std::string tool;
    std::string args;         // echoed assistant call
    std::string resultExcerpt;  // bounded excerpt
};

std::string excerpt(const std::string& s, size_t maxBytes) {
    if (s.size() <= maxBytes) return s;
    return s.substr(0, maxBytes) + "\n...[truncated " +
           std::to_string(s.size() - maxBytes) + " bytes]";
}

std::string buildPrompt(const std::string& systemPrompt,
                        const std::string& userRequest,
                        const std::vector<ToolTransaction>& history,
                        const std::string& stepInstruction) {
    std::ostringstream ctx;
    size_t from = history.size() > kMaxHistoryEntries
                      ? history.size() - kMaxHistoryEntries : 0;
    // Replay each transaction as its own assistant turn + user result turn so
    // the model sees exactly what IT called and what came back. This is the
    // coherence fix for the fabrication failure observed in the first smoke
    // run (model role-played results because its own calls were invisible).
    for (size_t i = from; i < history.size(); ++i) {
        ctx << "<|im_start|>assistant\n<tool>" << history[i].tool
            << "</tool>\n<args>" << history[i].args << "</args><|im_end|>\n"
            << "<|im_start|>user\n[TOOL RESULT for " << history[i].tool << "]\n"
            << history[i].resultExcerpt << "<|im_end|>\n";
    }

    std::ostringstream p;
    p << "<|im_start|>system\n" << systemPrompt
      << "<|im_end|>\n"
         "<|im_start|>user\n" << userRequest << "<|im_end|>\n";
    p << ctx.str();
    p << "<|im_start|>user\n" << stepInstruction << "<|im_end|>\n"
         "<|im_start|>assistant\n";
    return p.str();
}

const char* kAuditSystemPrompt =
    "You are a rigorous code auditor running inside the RawrXD runtime with "
    "read-only tool authority. You audit a repository for unfinished, fake, "
    "disabled, or stub implementations.\n\n"
    "PROTOCOL (strict):\n"
    "1. To call exactly ONE tool, reply with ONLY:\n"
    "   <tool>tool_name</tool>\n"
    "   <args>{\"param\":\"value\"}</args>\n"
    "2. When you have fully completed the request, reply with your final "
    "answer text (no tool tags).\n"
    "3. NEVER fabricate file contents or tool results.\n"
    "4. Work systematically: enumerate files, inspect suspicious candidates "
    "with file.read/code.search, record every finding with "
    "audit.add_candidate, review each candidate with audit.review, and mark "
    "inspected files with audit.files_reviewed.\n"
    "5. Before finishing, call audit.coverage and ensure every enumerated "
    "file is reviewed and every candidate has a verdict. The runtime refuses "
    "completion otherwise.\n\n";

} // namespace

void setKnownToolNames(const std::vector<std::string>& names) {
    knownTools() = names;
}

// ---------------------------------------------------------------------------
// The one loop.
// ---------------------------------------------------------------------------
AgentResult run_agent_session(RawrDeep2Runner& runner,
                              const std::string& userRequest,
                              const std::filesystem::path& workspaceRoot,
                              const AgentOptions& options,
                              bool auditMode) {
    AgentResult result;

    // Ledger + authority binding.
    AuditLedger ledger(workspaceRoot);
    if (auditMode) {
        ledger.enumerateSources();
        std::fprintf(stderr, "[RAWR_AGENT] audit files_enumerated=%llu\n",
                     static_cast<unsigned long long>(ledger.counters().filesEnumerated));
    }

    AgentToolRegistry authority;
    BindAgentToolAuthority(authority);
    registerAuditToolProviders(authority, &ledger);

    // Lenient-parse validation: only registered tools may be invoked from
    // bare-line replies.
    {
        std::vector<std::string> names;
        for (const auto& d : authority.list()) names.push_back(d.id);
        setKnownToolNames(names);
    }

    const std::string systemPrompt =
        options.systemPrompt.empty()
            ? std::string(kAuditSystemPrompt) + agentToolCatalogJson()
            : options.systemPrompt;

    std::vector<ToolTransaction> history;

    for (uint32_t step = 0; step < options.maxSteps; ++step) {
        result.steps = step + 1;

        const std::string stepInstruction =
            auditMode
                ? "Continue the audit. Call exactly one tool, or give your "
                  "final report when coverage is complete."
                : "Continue. Call exactly one tool, or give your final answer.";
        const std::string prompt = buildPrompt(systemPrompt, userRequest,
                                                history, stepInstruction);

        // Generation with stop-on-<|im_end|>.
        std::string replyText;
        RunStreamReceipt stepReceipt{};
        bool stoppedOnImEnd = false;
        Deep2::GenerationOptions gen{};
        gen.maxTokens = options.maxTokensPerStep;
        gen.temperature = 0.0f;
        gen.topK = 1;
        gen.topP = 1.0f;
        gen.repeatPenalty = 1.0f;
        gen.seed = 1;

        // reset() clears KV; each step re-feeds the compact context.
        runner.reset();
        const auto genResult = runner.engine().generateStream(
            prompt, gen,
            [&](int32_t, const std::string& piece) -> bool {
                replyText += piece;
                if (replyText.find("<|im_end|>") != std::string::npos) {
                    stoppedOnImEnd = true;
                    return false;  // stop generation
                }
                return true;
            });
        result.generatedTokens += genResult.generatedTokens;

        if (stoppedOnImEnd) {
            const size_t cut = replyText.find("<|im_end|>");
            replyText = replyText.substr(0, cut);
        }

        const ModelReply reply = parseReply(trim(replyText));

        if (reply.kind == ModelReply::Kind::Final) {
            result.reachedFinal = true;
            result.finalText = reply.text;
            break;
        }

        if (reply.kind == ModelReply::Kind::ProtocolError) {
            std::fprintf(stderr,
                         "[RAWR_AGENT] protocol error at step %u; raw reply:\n%.512s\n",
                         step, reply.text.c_str());
            result.status = "PROTOCOL_ERROR";
            return result;
        }

        // Tool dispatch through the bound authority.
        ToolRequest request;
        request.surface = AgentToolSurface::AgentCore;
        request.tool_id = reply.tool;
        request.stdin_text = reply.args;
        request.working_directory = workspaceRoot;

        ++result.toolCalls;
        const ToolResult toolResult = authority.invoke(request, {});
        if (!toolResult.ok()) {
            ++result.toolFailures;
            ledger.countToolFailure();
        }

        std::ostringstream tr;
        tr << (toolResult.ok() ? toolResult.stdout_text : toolResult.stderr_text);
        history.push_back({reply.tool, reply.args, excerpt(tr.str(), 4096)});

        std::fprintf(stderr, "[RAWR_AGENT] step=%u tool=%s exit=%d len=%zu\n",
                     step, reply.tool.c_str(), toolResult.exit_code,
                     tr.str().size());
    }

    // Completion authority — the runtime decides, never the model.
    if (auditMode) {
        const AuditCounters c = ledger.counters();
        result.coverageComplete = ledger.coverageComplete();
        ledger.writeSnapshot(workspaceRoot / ".rawr" / "audit_candidates.jsonl");

        std::fprintf(stderr,
                     "[RAWR_AGENT] COVERAGE\n"
                     "FILES_TOTAL=%llu\nFILES_ENUMERATED=%llu\nFILES_REVIEWED=%llu\n"
                     "CANDIDATES_TOTAL=%llu\nCANDIDATES_REVIEWED=%llu\n"
                     "CANDIDATES_PENDING=%llu\nTOOL_FAILURES=%llu\n"
                     "STEPS=%u TOOL_CALLS=%u GENERATED_TOKENS=%llu\n",
                     static_cast<unsigned long long>(c.filesTotal),
                     static_cast<unsigned long long>(c.filesEnumerated),
                     static_cast<unsigned long long>(c.filesReviewed),
                     static_cast<unsigned long long>(c.candidatesTotal),
                     static_cast<unsigned long long>(c.candidatesReviewed),
                     static_cast<unsigned long long>(c.candidatesPending),
                     static_cast<unsigned long long>(c.toolFailures),
                     result.steps, result.toolCalls,
                     static_cast<unsigned long long>(result.generatedTokens));
    }

    const bool ok = result.reachedFinal &&
                    (!auditMode || result.coverageComplete) &&
                    result.toolFailures == 0;
    result.status = ok ? "PASS" : "FAIL";
    result.exitCode = ok ? 0 : 1;
    return result;
}

} // namespace agent
} // namespace rawrxd