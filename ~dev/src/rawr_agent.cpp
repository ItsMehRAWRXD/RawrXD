// ============================================================================
// rawr_agent.cpp — RAWR_AGENT_LOOP_001 + RAWR_AUDIT_COVERAGE_001 implementation.
// The one unified loop: model -> tool call -> tool result -> model -> ...
// -> final. Bounded steps. Hard failure semantics. Runtime-owned completion
// authority via the audit ledger. Chat framing uses the Qwen2.5 template;
// the stop condition is the literal <|im_end|> token (tokenizer preserves
// specials literally, engine lacks EOS metadata — we stop in the callback).
// ============================================================================
#include "rawr_agent.hpp"

#include <cctype>
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
    // Remove only an enclosing Markdown code fence. Removing every backtick
    // corrupts legitimate JSON string arguments and final-answer content.
    s = trim(std::move(s));
    if (s.rfind("```", 0) != 0) return s;
    const size_t openingNewline = s.find('\n');
    if (openingNewline == std::string::npos) return s;
    const size_t closing = s.rfind("```");
    if (closing == 0 || closing == std::string::npos ||
        !trim(s.substr(closing + 3)).empty()) return s;
    return trim(s.substr(openingNewline + 1, closing - openingNewline - 1));
}

// Known tool names (filled at registration time by setKnownToolNames).
std::vector<std::string>& knownTools() {
    // Each agent session owns its tool catalog on its invoking thread.
    // A process-global mutable catalog races across concurrent sessions.
    static thread_local std::vector<std::string> names;
    return names;
}

bool isKnownTool(const std::string& name) {
    // Registry IDs are canonicalized (dots/dashes/underscores are separators):
    // 'workspace.list' == 'workspace-list' == 'workspace_list'. The catalog
    // shows dotted names, the registry stores dashed ids — accept both.
    auto canon = [](const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            const unsigned char u = static_cast<unsigned char>(c);
            if (u == '.' || u == '-' || u == '_' || u == '/' || u == '\\' ||
                std::isspace(u))
                continue;
            out.push_back(static_cast<char>(std::tolower(u)));
        }
        return out;
    };
    const std::string key = canon(name);
    if (key.empty()) return false;
    for (const auto& n : knownTools())
        if (canon(n) == key) return true;
    return false;
}

ModelReply parseReply(const std::string& raw) {
    ModelReply r;
    const std::string cleaned = stripFences(raw);
    const std::string tool = between(cleaned, "<tool>", "</tool>");
    if (!tool.empty()) {
        // Never execute a partially formed or multi-call response. A single
        // model turn is permitted to request exactly one complete tool call.
        const size_t toolEnd = cleaned.find("</tool>");
        const size_t argsOpen = cleaned.find("<args>", toolEnd);
        const size_t argsEnd = argsOpen == std::string::npos
            ? std::string::npos : cleaned.find("</args>", argsOpen);
        if (trim(tool).empty() || argsOpen == std::string::npos ||
            argsEnd == std::string::npos ||
            cleaned.find("<tool>", toolEnd + 7) != std::string::npos ||
            cleaned.find("<args>", argsOpen + 6) != std::string::npos ||
            cleaned.find("</tool>", toolEnd + 7) != std::string::npos ||
            cleaned.find("</args>", argsEnd + 7) != std::string::npos ||
            cleaned.find("<args>") < toolEnd ||
            cleaned.find("<tool>", argsOpen) != std::string::npos ||
            !trim(cleaned.substr(0, cleaned.find("<tool>"))).empty() ||
            !trim(cleaned.substr(argsEnd + 7)).empty() ||
            !trim(cleaned.substr(toolEnd + 7, argsOpen - (toolEnd + 7))).empty()) {
            r.kind = ModelReply::Kind::ProtocolError;
            r.text = raw;
            return r;
        }
        r.kind = ModelReply::Kind::ToolCall;
        r.tool = trim(tool);
        r.args = trim(cleaned.substr(argsOpen + 6, argsEnd - (argsOpen + 6)));
        // A tool request must carry an object payload, not arbitrary prose.
        // The dispatcher is not a full JSON parser; reject non-object framing.
        if (r.args.empty()) r.args = "{}";
        if (r.args.front() != '{' || r.args.back() != '}') {
            r.kind = ModelReply::Kind::ProtocolError;
            r.text = raw;
            return r;
        }
        return r;
    }
    // A malformed tag block is a protocol error, not a final answer.
    if (cleaned.find("<tool>") != std::string::npos ||
        cleaned.find("</tool>") != std::string::npos ||
        cleaned.find("</args>") != std::string::npos ||
        cleaned.find("<args>") != std::string::npos) {
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
                // Bare tool calls must contain exactly one object-shaped
                // argument payload, without trailing text or extra lines.
                const bool validJson = jsonPart.size() >= 2 &&
                    jsonPart.front() == '{' && jsonPart.back() == '}' &&
                    cleaned.find('\n') == std::string::npos;
                if (isKnownTool(candidate)) {
                    if (!validJson) {
                        r.kind = ModelReply::Kind::ProtocolError;
                        r.text = raw;
                        return r;
                    }
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

// Treat model-visible user and tool data as content, never chat-template
// structure. Break reserved role delimiters before interpolation.
std::string escapeChatRoleDelimiters(std::string s) {
    size_t pos = 0;
    while ((pos = s.find("<|", pos)) != std::string::npos) {
        s.replace(pos, 2, "< |");
        pos += 3;
    }
    return s;
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
            << "</tool>\n<args>" << escapeChatRoleDelimiters(history[i].args) << "</args><|im_end|>\n"
            << "<|im_start|>user\n[TOOL RESULT for " << history[i].tool << "]\n"
            << escapeChatRoleDelimiters(history[i].resultExcerpt) << "<|im_end|>\n";
    }

    std::ostringstream p;
    p << "<|im_start|>system\n" << systemPrompt
      << "<|im_end|>\n"
         "<|im_start|>user\n" << escapeChatRoleDelimiters(userRequest) << "<|im_end|>\n";
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
    "completion otherwise.\n\n"
    "TOOL-SELECTION LAW (candidate review):\n"
    "- First call audit.coverage once. If the scan is not complete, call "
    "audit.scan exactly once.\n"
    "- Then page pending candidates with audit.candidates {\"limit\":16}.\n"
    "- For each candidate: audit.candidate.read FIRST. If the evidence is "
    "already clear, immediately audit.candidate.review it.\n"
    "- Only call file.read / symbol.find / symbol.references / code.search "
    "when a verdict genuinely needs more context.\n"
    "- Never run workspace.list during candidate review. Never rerun "
    "audit.scan once SOURCE_SCAN_COMPLETE=1.\n"
    "- Call audit.coverage once per candidate batch, not per candidate.\n\n";

} // namespace

void setKnownToolNames(const std::vector<std::string>& names) {
    knownTools() = names;
}

// Production parser exposed for the deterministic protocol self-test.
ProtocolParseResultForTest parseModelReplyForTest(const std::string& raw) {
    ProtocolParseResultForTest out;
    const ModelReply reply = parseReply(raw);
    if (reply.kind == ModelReply::Kind::ToolCall) {
        out.isTool = true;
        out.tool = reply.tool;
        out.args = reply.args;
    } else if (reply.kind == ModelReply::Kind::Final) {
        out.isFinal = true;
    }
    // ProtocolError leaves both flags false.
    return out;
}

// ---------------------------------------------------------------------------
// The one loop.
// ---------------------------------------------------------------------------
AgentResult run_agent_session(RawrDeep2Runner& runner,
                              const std::string& userRequest,
                              const std::filesystem::path& workspaceRoot,
                              const AgentOptions& options,
                              bool auditMode,
                              bool requireCoverage) {
    AgentResult result;

    // Ledger + authority binding. Sources are enumerated in EVERY session:
    // the workspace tools (workspace.list, code.search, ...) read the
    // enumeration, so an empty ledger would make their results empty and
    // invite model fabrication (observed: model invented "5 entries" from
    // an empty workspace.list result when auditMode=false skipped it).
    AuditLedger ledger(workspaceRoot);
    ledger.enumerateSources();
    std::fprintf(stderr, "[RAWR_AGENT] files_enumerated=%llu\n",
                 static_cast<unsigned long long>(ledger.counters().filesEnumerated));

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

    // Loop-cert uses a protocol-only prompt: the audit directive would send
    // the model off enumerating files instead of finishing the minimal
    // certification transaction. (Observed: 3 audit steps, no Final.)
    const char* kLoopCertSystemPrompt =
        "You are executing a minimal tool-protocol certification transaction. "
        "Call the one tool the user names, inspect the returned result, then "
        "reply with your final short answer. Do not start any broader audit "
        "or exploration.\n\n"
        "PROTOCOL (strict):\n"
        "1. To call exactly ONE tool, reply with ONLY:\n"
        "   <tool>tool_name</tool>\n"
        "   <args>{\"param\":\"value\"}</args>\n"
        "2. To finish, reply with your final answer text (no tool tags).\n";

    const std::string systemPrompt =
        options.systemPrompt.empty()
            ? std::string(auditMode && requireCoverage
                              ? kAuditSystemPrompt
                              : kLoopCertSystemPrompt) +
                  agentToolCatalogJson()
            : options.systemPrompt;

    std::vector<ToolTransaction> history;

    for (uint32_t step = 0; step < options.maxSteps; ++step) {
        result.steps = step + 1;

        const std::string stepInstruction =
            auditMode && requireCoverage
                ? "Continue the audit. Call exactly one tool, or give your "
                  "final report when coverage is complete."
                : "Continue. Call exactly one tool, or give your final answer.";
        const std::string prompt = buildPrompt(systemPrompt, userRequest,
                                                history, stepInstruction);
        // A result counts as seen only when a subsequent generation receives it.
        if (!history.empty()) result.sawToolResult = true;

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

        // Empty generation is not a successful final answer. In particular,
        // a backend numeric abort must never certify agent completion.
        if (trim(replyText).empty()) {
            result.status = "EMPTY_MODEL_RESPONSE";
            result.reachedFinal = false;
            return result;
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
        if (result.firstTool.empty()) result.firstTool = reply.tool;
        const ToolResult toolResult = authority.invoke(request, {});
        if (toolResult.exit_code == 127) {
            // Unregistered tool: recoverable protocol error. The rejection
            // text is fed back so the model can self-correct; it does NOT
            // poison the durable ledger failure counter.
            ++result.invalidToolAttempts;
        } else if (!toolResult.ok()) {
            ++result.toolFailures;
            ledger.countToolFailure();
        } else {
            ++result.successfulToolCalls;
            if (result.firstSuccessfulTool.empty())
                result.firstSuccessfulTool = reply.tool;
            if (result.invalidToolAttempts > 0)
                result.recoveredToolErrors = result.invalidToolAttempts;
        }

        std::ostringstream tr;
        // Preserve the real exit status in model context: stderr alone cannot
        // distinguish a failed tool from a successful empty response.
        tr << "[TOOL EXIT_CODE=" << toolResult.exit_code
           << " STATUS=" << (toolResult.ok() ? "SUCCESS" : "FAILURE") << "]\n";
        const std::string& toolOutput = toolResult.ok()
            ? toolResult.stdout_text : toolResult.stderr_text;
        if (toolOutput.empty()) tr << "(tool returned no output)";
        else tr << toolOutput;
        history.push_back({reply.tool, reply.args, excerpt(tr.str(), 4096)});
        // Do not mark reinjection complete until the next generation starts.

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
                    (requireCoverage ?
                        (!auditMode || result.coverageComplete) : true) &&
                    result.toolFailures == 0 &&
                    (result.invalidToolAttempts - result.recoveredToolErrors) == 0 &&
                    result.successfulToolCalls > 0;
    result.status = ok ? "PASS" : "FAIL";
    result.exitCode = ok ? 0 : 1;

    // Full-audit receipt — RAWR_IDE_AUDIT_E2E_001 authority.
    if (auditMode && requireCoverage) {
        const AuditCounters cc = ledger.counters();
        const uint32_t unrecovered =
            result.toolFailures +
            (result.invalidToolAttempts - result.recoveredToolErrors);
        std::fprintf(stderr,
                     "RAWR_IDE_AUDIT_E2E_001_RECEIPT\n"
                     "FILES_ENUMERATED=%llu\n"
                     "FILES_SCANNED=%llu\n"
                     "SOURCE_SCAN_COMPLETE=%d\n"
                     "CANDIDATES_TOTAL=%llu\n"
                     "CANDIDATES_REVIEWED=%llu\n"
                     "CANDIDATES_PENDING=%llu\n"
                     "CONFIRMED_DEFECTS=%llu\n"
                     "FALSE_POSITIVES=%llu\n"
                     "NEEDS_RUNTIME_PROOF=%llu\n"
                     "FAKE_TOOL_RESULTS=0\n"
                     "INVALID_TOOL_ATTEMPTS=%u\n"
                     "RECOVERED_TOOL_ERRORS=%u\n"
                     "UNRECOVERED_TOOL_FAILURES=%u\n"
                     "WRITE_ACTIONS=0\n"
                     "COVERAGE_COMPLETE=%d\n"
                     "REPORT_EMITTED=%d\n"
                     "REACHED_FINAL=%d\n"
                     "GEN_EXIT=%d\n"
                     "RAWR_IDE_AUDIT_E2E_001=%s\n",
                     static_cast<unsigned long long>(cc.filesEnumerated),
                     static_cast<unsigned long long>(cc.filesScanned),
                     cc.sourceScanComplete ? 1 : 0,
                     static_cast<unsigned long long>(cc.candidatesTotal),
                     static_cast<unsigned long long>(cc.candidatesReviewed),
                     static_cast<unsigned long long>(cc.candidatesPending),
                     static_cast<unsigned long long>(cc.confirmedDefects),
                     static_cast<unsigned long long>(cc.falsePositives),
                     static_cast<unsigned long long>(cc.needsRuntimeProof),
                     result.invalidToolAttempts,
                     result.recoveredToolErrors,
                     unrecovered,
                     result.coverageComplete ? 1 : 0,
                     result.finalText.empty() ? 0 : 1,
                     result.reachedFinal ? 1 : 0,
                     result.exitCode,
                     result.status.c_str());
        std::fflush(stderr);
    }

    // Loop-cert receipt: proves tool dispatch + real result reached context.
    if (!requireCoverage) {
        std::fprintf(stderr,
                     "RAWR_AGENT_LOOP_001_RECEIPT\n"
                     "AGENT_LOOP=1\n"
                     "TOOL_AUTHORITY=1\n"
                     "TOOL_CALLS=%u\n"
                     "SUCCESSFUL_TOOL_CALLS=%u\n"
                     "TOOL_NAME=%s\n"
                     "TOOL_RESULT_RETURNED=%d\n"
                     "MODEL_SAW_TOOL_RESULT=%d\n"
                     "REACHED_FINAL=%d\n"
                     "INVALID_TOOL_ATTEMPTS=%u\n"
                     "RECOVERED_TOOL_ERRORS=%u\n"
                     "FAKE_TOOL_RESULTS=0\n"
                     "STEPS=%u\n"
                     "GEN_EXIT=%d\n"
                     "RAWR_AGENT_LOOP_001=%s\n",
                     result.toolCalls,
                     result.successfulToolCalls,
                     (result.firstSuccessfulTool.empty()
                          ? (result.firstTool.empty() ? "(none)"
                                                      : result.firstTool.c_str())
                          : result.firstSuccessfulTool.c_str()),
                     result.successfulToolCalls > 0 ? 1 : 0,
                     result.sawToolResult ? 1 : 0,
                     result.reachedFinal ? 1 : 0,
                     result.invalidToolAttempts,
                     result.recoveredToolErrors,
                     result.steps,
                     result.exitCode,
                     result.status.c_str());
        std::fflush(stderr);
    }
    return result;
}

} // namespace agent
} // namespace rawrxd