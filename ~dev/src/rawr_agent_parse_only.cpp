// ============================================================================
// rawr_agent_parse_only.cpp — RAWR_AGENT_PROTOCOL_SELFTEST_001 support TU.
// The EXACT production reply parser (copied verbatim from rawr_agent.cpp's
// internal contract) compiled without the Deep2Engine header chain so the
// self-test needs no Vulkan headers. rawr_agent.cpp asserts behavioral
// equality at build time via the same ProtocolParseResultForTest entry —
// when the selftest links, the parse contract below is the same one the
// loop uses; any divergence shows up as a selftest case failure.
// ============================================================================
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <sstream>
#include <string>
#include <vector>

#include "rawr_agent.hpp"

namespace rawrxd {
namespace agent {

namespace {

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
    static std::vector<std::string> names;
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
            cleaned.find("<tool>", argsOpen) != std::string::npos) {
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
    return out;
}

} // namespace agent
} // namespace rawrxd