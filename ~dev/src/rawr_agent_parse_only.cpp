// ============================================================================
// rawr_agent_parse_only.cpp — RAWR_AGENT_PROTOCOL_SELFTEST_001 support TU.
// Portable copy of the production reply parser for Vulkan-free tests.
// Keep this in sync until the parser is extracted into a shared unit.
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
                    cleaned.find('\\n') == std::string::npos;
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