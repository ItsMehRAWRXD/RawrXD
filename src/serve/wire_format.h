// ============================================================================
// wire_format.h — Universal wire format adapter interface
// No Ollama. No assumptions. OpenAI + Anthropic + RawrXD-native health.
// ============================================================================
#pragma once

#include <string>
#include <vector>
#include <map>
#include <functional>
#include <memory>
#include <sstream>
#include <cstdio>
#include <chrono>
#include <ctime>

namespace RawrXD::Serve {

// ============================================================================
// Chat message
// ============================================================================
struct ChatMessage {
    std::string role;
    std::string content;
};

// ============================================================================
// Generate request (protocol-agnostic)
// ============================================================================
struct GenerateRequest {
    std::string model;
    std::string prompt;
    std::vector<ChatMessage> messages;
    bool stream = true;
    float temperature = 0.7f;
    int num_predict = 512;
    float top_p = 0.9f;
    int top_k = 40;
    float repeat_penalty = 1.1f;
    int seed = -1;
    std::string system;
    std::string stop;
    std::map<std::string, std::string> raw;
};

// ============================================================================
// Generation chunk (token stream)
// ============================================================================
struct GenerationChunk {
    std::string token;
    bool done = false;
    std::string finish_reason;
    int prompt_tokens = 0;
    int completion_tokens = 0;
    std::map<std::string, std::string> raw;
};

using TokenCallback = std::function<void(const GenerationChunk&)>;

// ============================================================================
// Model entry (for model listing)
// ============================================================================
struct ModelEntry {
    std::string name;
    std::string path;
    std::string architecture;
    std::string quantization;
    std::string param_count;
    uint64_t fileSizeBytes = 0;
};

// ============================================================================
// JSON escape helper
// ============================================================================
inline std::string esc(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

// ============================================================================
// JSON object builder (inline, header-only)
// ============================================================================
class JsonObj {
    std::ostringstream m_ss;
    bool m_first = true;
public:
    JsonObj() { m_ss << '{'; }
    JsonObj& kv(const char* k, const std::string& v) {
        sep(); m_ss << '"' << k << "\":\"" << esc(v) << '"'; return *this;
    }
    JsonObj& kv(const char* k, int64_t v) {
        sep(); m_ss << '"' << k << "\":" << v; return *this;
    }
    JsonObj& kv(const char* k, uint64_t v) {
        sep(); m_ss << '"' << k << "\":" << v; return *this;
    }
    JsonObj& kv(const char* k, int v) { return kv(k, static_cast<int64_t>(v)); }
    JsonObj& kv(const char* k, double v) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "%.6g", v);
        sep(); m_ss << '"' << k << "\":" << buf; return *this;
    }
    JsonObj& kv(const char* k, bool v) {
        sep(); m_ss << '"' << k << "\":" << (v ? "true" : "false"); return *this;
    }
    JsonObj& kvRaw(const char* k, const std::string& raw) {
        sep(); m_ss << '"' << k << "\":" << raw; return *this;
    }
    std::string build() { m_ss << '}'; return m_ss.str(); }
private:
    void sep() { if (!m_first) m_ss << ','; m_first = false; }
};

// ============================================================================
// JSON reader helpers (flat objects only — sufficient for OpenAI/Anthropic)
// ============================================================================
namespace json {

inline std::string findString(const std::string& body, const char* key) {
    std::string needle = std::string("\"") + key + "\"";
    auto pos = body.find(needle);
    if (pos == std::string::npos) return {};
    pos = body.find(':', pos + needle.size());
    if (pos == std::string::npos) return {};
    pos++;
    while (pos < body.size() && (body[pos] == ' ' || body[pos] == '\t')) pos++;
    if (pos >= body.size() || body[pos] != '"') return {};
    pos++;
    std::string out;
    while (pos < body.size() && body[pos] != '"') {
        if (body[pos] == '\\' && pos + 1 < body.size()) {
            pos++;
            switch (body[pos]) {
                case 'n': out += '\n'; break;
                case 't': out += '\t'; break;
                case 'r': out += '\r'; break;
                case '\\': out += '\\'; break;
                case '"': out += '"'; break;
                case '/': out += '/'; break;
                case 'u': {
                    if (pos + 4 < body.size()) {
                        unsigned cp = 0;
                        for (int i = 0; i < 4; i++) {
                            char c = body[pos + 1 + i];
                            cp <<= 4;
                            if (c >= '0' && c <= '9') cp |= (c - '0');
                            else if (c >= 'a' && c <= 'f') cp |= (c - 'a' + 10);
                            else if (c >= 'A' && c <= 'F') cp |= (c - 'A' + 10);
                        }
                        if (cp < 0x80) out += static_cast<char>(cp);
                        else if (cp < 0x800) {
                            out += static_cast<char>(0xC0 | (cp >> 6));
                            out += static_cast<char>(0x80 | (cp & 0x3F));
                        } else {
                            out += static_cast<char>(0xE0 | (cp >> 12));
                            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
                            out += static_cast<char>(0x80 | (cp & 0x3F));
                        }
                        pos += 4;
                    }
                    break;
                }
                default: out += body[pos]; break;
            }
        } else {
            out += body[pos];
        }
        pos++;
    }
    return out;
}

inline int findInt(const std::string& body, const char* key, int def) {
    std::string needle = std::string("\"") + key + "\"";
    auto pos = body.find(needle);
    if (pos == std::string::npos) return def;
    pos = body.find(':', pos + needle.size());
    if (pos == std::string::npos) return def;
    pos++;
    while (pos < body.size() && body[pos] == ' ') pos++;
    if (pos >= body.size()) return def;
    bool neg = (body[pos] == '-');
    if (neg) pos++;
    int val = 0;
    bool any = false;
    while (pos < body.size() && body[pos] >= '0' && body[pos] <= '9') {
        val = val * 10 + (body[pos] - '0');
        pos++; any = true;
    }
    return any ? (neg ? -val : val) : def;
}

inline float findFloat(const std::string& body, const char* key, float def) {
    std::string needle = std::string("\"") + key + "\"";
    auto pos = body.find(needle);
    if (pos == std::string::npos) return def;
    pos = body.find(':', pos + needle.size());
    if (pos == std::string::npos) return def;
    pos++;
    while (pos < body.size() && body[pos] == ' ') pos++;
    size_t start = pos;
    while (pos < body.size() &&
           (body[pos] == '.' || body[pos] == '-' ||
            (body[pos] >= '0' && body[pos] <= '9') ||
            body[pos] == 'e' || body[pos] == 'E'))
        pos++;
    if (pos == start) return def;
    return std::strtof(body.c_str() + start, nullptr);
}

inline bool findBool(const std::string& body, const char* key, bool def) {
    std::string needle = std::string("\"") + key + "\"";
    auto pos = body.find(needle);
    if (pos == std::string::npos) return def;
    pos = body.find(':', pos + needle.size());
    if (pos == std::string::npos) return def;
    pos++;
    while (pos < body.size() && body[pos] == ' ') pos++;
    if (pos < body.size() && body[pos] == 't') return true;
    if (pos < body.size() && body[pos] == 'f') return false;
    return def;
}

inline std::vector<ChatMessage> findMessages(const std::string& body) {
    std::vector<ChatMessage> msgs;
    auto arrStart = body.find("\"messages\"");
    if (arrStart == std::string::npos) return msgs;
    arrStart = body.find('[', arrStart);
    if (arrStart == std::string::npos) return msgs;

    size_t pos = arrStart + 1;
    while (pos < body.size()) {
        auto objStart = body.find('{', pos);
        if (objStart == std::string::npos) break;
        int depth = 1;
        size_t objEnd = objStart + 1;
        while (objEnd < body.size() && depth > 0) {
            if (body[objEnd] == '{') depth++;
            else if (body[objEnd] == '}') depth--;
            objEnd++;
        }
        if (depth != 0) break;

        std::string obj = body.substr(objStart, objEnd - objStart);
        ChatMessage m;
        m.role    = findString(obj, "role");
        m.content = findString(obj, "content");
        if (!m.role.empty()) msgs.push_back(std::move(m));

        pos = objEnd;
        size_t close = body.find(']', pos);
        size_t nextOpen = body.find('{', pos);
        if (close != std::string::npos && (nextOpen == std::string::npos || close < nextOpen))
            break;
    }
    return msgs;
}

} // namespace json

// ============================================================================
// ISO 8601 timestamp
// ============================================================================
inline std::string isoTimestamp() {
    auto now = std::chrono::system_clock::now();
    time_t tt = std::chrono::system_clock::to_time_t(now);
    struct tm utc;
#ifdef _MSC_VER
    gmtime_s(&utc, &tt);
#else
    gmtime_r(&tt, &utc);
#endif
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &utc);
    return buf;
}

// ============================================================================
// Wire format adapter interface
// ============================================================================
class WireFormatAdapter {
public:
    virtual ~WireFormatAdapter() = default;
    virtual std::string name() const = 0;

    // Path match (no trailing slash). Method match is "GET" or "POST".
    virtual bool match(const std::string& path, const std::string& method) const = 0;

    // POST: parse request body into a GenerateRequest
    virtual GenerateRequest parseRequest(const std::string& body) const = 0;

    // Streaming chunk serialization (SSE frame). Adapter chooses wire format.
    virtual std::string buildStreamingChunk(
        const std::string& model,
        const GenerationChunk& chunk,
        const GenerateRequest& req) const = 0;

    // Non-streaming final response
    virtual std::string buildFinalResponse(
        const std::string& model,
        const std::string& fullText,
        const GenerateRequest& req) const = 0;

    // GET: list models in this adapter's wire format
    virtual std::string listModelsJson(const std::vector<ModelEntry>& models) const = 0;

    // Streaming content-type header
    virtual std::string streamContentType() const = 0;

    // Streaming terminator (e.g. "data: [DONE]\n\n" or empty for Anthropic)
    virtual std::string streamTerminator() const = 0;
};

} // namespace RawrXD::Serve
