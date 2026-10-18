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
    std::string args;
    std::string text;
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

std::string stripFences(std::string s) {
    auto eraseAll = [&](const std::string& t) {
        size_t p;
        while ((p = s.find(t)) != std::string::npos) s.erase(p, t.size());
    };
    eraseAll("```");
    return s;
}

std::vector<std::string>& knownTools() {
    static std::vector<std::string> names;
    return names;
}

bool isKnownTool(const std::string& name) {
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
        r.kind = ModelReply::Kind::ToolCall;
        r.tool = trim(tool);
        r.args = between(cleaned, "<args>", "</args>");
        if (r.args.empty()) r.args = "{}";
        return r;
    }
    if (cleaned.find("<args>") != std::string::npos) {
        r.kind = ModelReply::Kind::ProtocolError;
        r.text = raw;
        return r;
    }
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