/*
===============================================================================
 RawrXD Sovereign Agentic Runtime — Zero-Dependency Closure Source
 File: src/agentic/rawrxd_agentic_runtime_all.cpp

 This source has ZERO external inference dependencies:
   - NO Ollama backend
   - NO cloud API calls
   - NO network/HTTP/cURL
   - NO placeholder or stub inference paths

 It binds exclusively to the real Deep2Engine generation surface via
 compile-time concept detection. If Deep2Engine does not expose a real
 generate() or generateStream() API, the build fails at compile time.

 Supported Deep2 shapes (auto-detected):
   engine.generateStream(prompt, maxTokens, callback)
   engine.generate(prompt, maxTokens) -> string
   engine.loadModel(path) / engine.load(path)
   Deep2Engine(path) constructor

===============================================================================
*/

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cerrno>
#include <charconv>
#include <condition_variable>
#include <cstring>
#include <concepts>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

#if __has_include("../deep2/Deep2Engine.hpp")
#include "../deep2/Deep2Engine.hpp"
#elif __has_include("../deep2/Deep2Engine.h")
#include "../deep2/Deep2Engine.h"
#elif __has_include("Deep2Engine.hpp")
#include "Deep2Engine.hpp"
#elif __has_include("Deep2Engine.h")
#include "Deep2Engine.h"
#else
#error "RawrXD unified agentic runtime requires the real Deep2Engine header."
#endif

#include "../models/ModelCatalog.hpp"
#include "HexMagRepeatTunerBridge.hpp"

#ifndef RAWRXD_DEEP2_ENGINE_TYPE
#define RAWRXD_DEEP2_ENGINE_TYPE Deep2::Deep2Engine
#endif

namespace rawrxd::agentic {

using Deep2 = RAWRXD_DEEP2_ENGINE_TYPE;
namespace fs = std::filesystem;

// =============================================================================
// Utilities
// =============================================================================

static std::string trim(std::string s) {
    auto nonSpace = [](unsigned char c) { return !std::isspace(c); };
    auto b = std::find_if(s.begin(), s.end(), nonSpace);
    auto e = std::find_if(s.rbegin(), s.rend(), nonSpace).base();
    if (b >= e) return {};
    return std::string(b, e);
}

static std::string lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
        [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

static bool startsWith(std::string_view text, std::string_view prefix) {
    return text.size() >= prefix.size() && text.substr(0, prefix.size()) == prefix;
}

static std::string readWholeFile(const fs::path& path, std::size_t maximum = 64ull * 1024ull * 1024ull) {
    std::error_code ec;
    const auto size = fs::file_size(path, ec);
    if (ec) throw std::runtime_error("unable to stat file: " + path.string());
    if (size > maximum) throw std::runtime_error("file exceeds configured maximum: " + path.string());
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("unable to open file: " + path.string());
    std::string data;
    data.resize(static_cast<std::size_t>(size));
    if (!data.empty()) {
        input.read(data.data(), static_cast<std::streamsize>(data.size()));
        if (!input) throw std::runtime_error("failed reading file: " + path.string());
    }
    return data;
}

static void writeWholeFile(const fs::path& path, std::string_view data) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) throw std::runtime_error("unable to open output file: " + path.string());
    output.write(data.data(), static_cast<std::streamsize>(data.size()));
    if (!output) throw std::runtime_error("failed writing file: " + path.string());
}

static std::string jsonEscape(std::string_view input) {
    std::ostringstream out;
    for (unsigned char c : input) {
        switch (c) {
        case '"': out << "\\\""; break;
        case '\\': out << "\\\\"; break;
        case '\b': out << "\\b"; break;
        case '\f': out << "\\f"; break;
        case '\n': out << "\\n"; break;
        case '\r': out << "\\r"; break;
        case '\t': out << "\\t"; break;
        default:
            if (c < 0x20) {
                out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c) << std::dec;
            } else {
                out << static_cast<char>(c);
            }
        }
    }
    return out.str();
}

static std::string jsonQuote(std::string_view input) {
    return "\"" + jsonEscape(input) + "\"";
}

static std::string isoTimeNow() {
    using namespace std::chrono;
    const auto now = system_clock::now();
    const std::time_t tt = system_clock::to_time_t(now);
    std::tm tm{};
#ifdef _WIN32
    gmtime_s(&tm, &tt);
#else
    gmtime_r(&tt, &tm);
#endif
    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return out.str();
}

// =============================================================================
// Minimal JSON field scanner
// =============================================================================

struct JsonSlice {
    std::size_t begin = 0;
    std::size_t end = 0;
};

static std::size_t skipWs(std::string_view s, std::size_t i) {
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
    return i;
}

static std::optional<JsonSlice> scanJsonString(std::string_view s, std::size_t start) {
    if (start >= s.size() || s[start] != '"') return std::nullopt;
    bool escaped = false;
    for (std::size_t i = start + 1; i < s.size(); ++i) {
        const char c = s[i];
        if (escaped) { escaped = false; continue; }
        if (c == '\\') { escaped = true; continue; }
        if (c == '"') return JsonSlice{start, i + 1};
    }
    return std::nullopt;
}

static std::optional<JsonSlice> scanBalancedJson(std::string_view s, std::size_t start) {
    if (start >= s.size()) return std::nullopt;
    const char opener = s[start];
    const char closer = opener == '{' ? '}' : opener == '[' ? ']' : '\0';
    if (!closer) return std::nullopt;
    int depth = 0;
    bool inString = false;
    bool escaped = false;
    for (std::size_t i = start; i < s.size(); ++i) {
        const char c = s[i];
        if (inString) {
            if (escaped) { escaped = false; }
            else if (c == '\\') { escaped = true; }
            else if (c == '"') { inString = false; }
            continue;
        }
        if (c == '"') { inString = true; continue; }
        if (c == opener) { ++depth; }
        else if (c == closer) { --depth; if (depth == 0) return JsonSlice{start, i + 1}; }
    }
    return std::nullopt;
}

static std::optional<JsonSlice> scanJsonValue(std::string_view s, std::size_t start) {
    start = skipWs(s, start);
    if (start >= s.size()) return std::nullopt;
    if (s[start] == '"') return scanJsonString(s, start);
    if (s[start] == '{' || s[start] == '[') return scanBalancedJson(s, start);
    std::size_t end = start;
    while (end < s.size()) {
        const char c = s[end];
        if (c == ',' || c == '}' || c == ']' || std::isspace(static_cast<unsigned char>(c))) break;
        ++end;
    }
    if (end == start) return std::nullopt;
    return JsonSlice{start, end};
}

static std::string unescapeJsonString(std::string_view quoted) {
    if (quoted.size() < 2 || quoted.front() != '"' || quoted.back() != '"') return std::string(quoted);
    std::string out;
    for (std::size_t i = 1; i + 1 < quoted.size(); ++i) {
        char c = quoted[i];
        if (c != '\\') { out.push_back(c); continue; }
        if (i + 1 >= quoted.size() - 1) break;
        const char e = quoted[++i];
        switch (e) {
        case '"': out.push_back('"'); break;
        case '\\': out.push_back('\\'); break;
        case '/': out.push_back('/'); break;
        case 'b': out.push_back('\b'); break;
        case 'f': out.push_back('\f'); break;
        case 'n': out.push_back('\n'); break;
        case 'r': out.push_back('\r'); break;
        case 't': out.push_back('\t'); break;
        case 'u':
            if (i + 4 < quoted.size() - 1) {
                unsigned value = 0; bool valid = true;
                for (int n = 0; n < 4; ++n) {
                    const char h = quoted[i + 1 + n];
                    int digit = -1;
                    if (h >= '0' && h <= '9') digit = h - '0';
                    else if (h >= 'a' && h <= 'f') digit = h - 'a' + 10;
                    else if (h >= 'A' && h <= 'F') digit = h - 'A' + 10;
                    else { valid = false; break; }
                    value = (value << 4) | static_cast<unsigned>(digit);
                }
                if (valid && value <= 0x7f) { out.push_back(static_cast<char>(value)); i += 4; }
                else { out += "\\u"; }
            } else { out += "\\u"; }
            break;
        default: out.push_back(e); break;
        }
    }
    return out;
}

static std::optional<JsonSlice> jsonFieldSlice(std::string_view object, std::string_view key) {
    std::size_t i = 0;
    while (i < object.size()) {
        i = object.find('"', i);
        if (i == std::string_view::npos) return std::nullopt;
        const auto keySlice = scanJsonString(object, i);
        if (!keySlice) return std::nullopt;
        const std::string decodedKey = unescapeJsonString(object.substr(keySlice->begin, keySlice->end - keySlice->begin));
        i = keySlice->end;
        i = skipWs(object, i);
        if (i >= object.size() || object[i] != ':') continue;
        ++i;
        if (decodedKey == key) return scanJsonValue(object, i);
        const auto value = scanJsonValue(object, i);
        if (!value) return std::nullopt;
        i = value->end;
    }
    return std::nullopt;
}

static std::optional<std::string> jsonStringField(std::string_view object, std::string_view key) {
    const auto slice = jsonFieldSlice(object, key);
    if (!slice) return std::nullopt;
    const auto raw = object.substr(slice->begin, slice->end - slice->begin);
    if (raw.size() < 2 || raw.front() != '"' || raw.back() != '"') return std::nullopt;
    return unescapeJsonString(raw);
}

static std::optional<std::string> jsonRawField(std::string_view object, std::string_view key) {
    const auto slice = jsonFieldSlice(object, key);
    if (!slice) return std::nullopt;
    return std::string(object.substr(slice->begin, slice->end - slice->begin));
}

static std::optional<std::int64_t> jsonIntegerField(std::string_view object, std::string_view key) {
    const auto raw = jsonRawField(object, key);
    if (!raw) return std::nullopt;
    std::int64_t value = 0;
    const auto result = std::from_chars(raw->data(), raw->data() + raw->size(), value);
    if (result.ec != std::errc{} || result.ptr != raw->data() + raw->size()) return std::nullopt;
    return value;
}

// =============================================================================
// GGUF metadata reader
// =============================================================================

enum class GgufType : std::uint32_t {
    UInt8 = 0, Int8 = 1, UInt16 = 2, Int16 = 3, UInt32 = 4, Int32 = 5,
    Float32 = 6, Bool = 7, String = 8, Array = 9, UInt64 = 10,
    Int64 = 11, Float64 = 12
};

class BinaryReader final {
public:
    explicit BinaryReader(const fs::path& path) : input_(path, std::ios::binary) {
        if (!input_) throw std::runtime_error("unable to open GGUF: " + path.string());
    }
    template <typename T> T read() {
        T value{};
        input_.read(reinterpret_cast<char*>(&value), sizeof(value));
        if (!input_) throw std::runtime_error("unexpected end of GGUF");
        return value;
    }
    std::string readString() {
        const std::uint64_t length = read<std::uint64_t>();
        if (length > 256ull * 1024ull * 1024ull) throw std::runtime_error("GGUF string length is unreasonable");
        std::string value;
        value.resize(static_cast<std::size_t>(length));
        if (!value.empty()) {
            input_.read(value.data(), static_cast<std::streamsize>(value.size()));
            if (!input_) throw std::runtime_error("unexpected end of GGUF string");
        }
        return value;
    }
    void skip(std::uint64_t count) {
        input_.seekg(static_cast<std::streamoff>(count), std::ios::cur);
        if (!input_) throw std::runtime_error("GGUF skip failed");
    }
private:
    std::ifstream input_;
};

struct GgufMetadata {
    std::uint32_t version = 0;
    std::uint64_t tensorCount = 0;
    std::string architecture;
    std::string modelName;
    std::string chatTemplate;
    std::string tokenizerModel;
    std::int64_t bosToken = -1;
    std::int64_t eosToken = -1;
    bool addBos = false;
    bool addEos = false;
    // Resolved from tokenizer.ggml.tokens[id] (empty if unavailable).
    std::string bosTokenStr;
    std::string eosTokenStr;
    // Vocab presence for chat markers (scanned while loading tokens).
    bool vocabHasEndTag = false;      // <|end|>
    bool vocabHasImEnd = false;       // <|im_end|>
    bool vocabHasImStart = false;     // <|im_start|>
    bool vocabHasUserTag = false;     // <|user|>
    bool vocabHasAssistantTag = false;
    bool vocabHasSystemTag = false;
    bool vocabHasToolTag = false;     // <|tool|>
};

// Reverse-engineered chat render contract from GGUF jinja + vocab.
// Sorts out mismatches like jinja saying <|end|> while vocab only has </s>,
// or renderers inventing <|tool|> when the template never trained that role.
struct TemplateContract {
    std::string messageStop;   // appended after each message body
    std::string assistantPrompt; // generation prompt suffix
    bool jinjaUsesEosVar = false;
    bool jinjaHasToolRole = false;
    bool remapToolToUser = true;
    std::string familyHint;    // diagnostic
};

static TemplateContract inferTemplateContract(const GgufMetadata& m) {
    TemplateContract c;
    const std::string& tmpl = m.chatTemplate;
    const std::string eos = !m.eosTokenStr.empty() ? m.eosTokenStr : "</s>";

    c.jinjaUsesEosVar = tmpl.find("eos_token") != std::string::npos;
    // Jinja mentions of a tool role (role == 'tool' / <|tool|>).
    c.jinjaHasToolRole =
        tmpl.find("role'] == 'tool'") != std::string::npos ||
        tmpl.find("role\"] == \"tool\"") != std::string::npos ||
        tmpl.find("<|tool|>") != std::string::npos ||
        (tmpl.find("'tool'") != std::string::npos &&
         tmpl.find("message['role']") != std::string::npos);
    // Heuristic: if template never defines tool handling, never emit <|tool|>.
    c.remapToolToUser = !c.jinjaHasToolRole || !m.vocabHasToolTag;

    // Message stop: follow jinja, but self-heal when the literal stop tag is absent from vocab.
    if (c.jinjaUsesEosVar) {
        c.messageStop = eos;
        c.familyHint = "eos_token";
    } else if (tmpl.find("<|im_end|>") != std::string::npos) {
        c.messageStop = (m.vocabHasImEnd || m.vocabHasImStart) ? "<|im_end|>" : eos;
        if (c.messageStop == eos) c.familyHint = "im_end->eos_heal";
        else c.familyHint = "im_end";
    } else if (tmpl.find("<|eot_id|>") != std::string::npos) {
        c.messageStop = "<|eot_id|>";
        c.familyHint = "eot_id";
    } else if (tmpl.find("<|end|>") != std::string::npos) {
        // Classic footgun: Phi-3-style jinja copied onto llama SPM vocabs that only have </s>.
        if (!m.vocabHasEndTag) {
            c.messageStop = eos;
            c.familyHint = "end_tag->eos_heal";
        } else {
            c.messageStop = "<|end|>";
            c.familyHint = "end_tag";
        }
    } else if (tmpl.find("<end_of_turn>") != std::string::npos) {
        c.messageStop = "<end_of_turn>";
        c.familyHint = "gemma_eot";
    } else {
        c.messageStop = eos;
        c.familyHint = "default_eos";
    }

    // Assistant generation prompt from jinja last-branch patterns.
    if (tmpl.find("<|im_start|>") != std::string::npos) {
        c.assistantPrompt = "<|im_start|>assistant\n";
    } else if (tmpl.find("<|start_header_id|>") != std::string::npos) {
        c.assistantPrompt = "<|start_header_id|>assistant<|end_header_id|>\n\n";
    } else if (tmpl.find("<|assistant|>") != std::string::npos) {
        // TinyLlama/Zephyr jinja: {{ '<|assistant|>' }} with no trailing stop.
        c.assistantPrompt = "<|assistant|>\n";
    } else if (tmpl.find("<start_of_turn>") != std::string::npos) {
        c.assistantPrompt = "<start_of_turn>model\n";
    } else {
        c.assistantPrompt = "assistant: ";
    }

    return c;
}

class GgufMetadataReader final {
public:
    static GgufMetadata read(const fs::path& path) {
        BinaryReader r(path);
        const std::uint32_t magic = r.read<std::uint32_t>();
        if (magic != 0x46554747u) throw std::runtime_error("not a GGUF model");
        GgufMetadata m;
        m.version = r.read<std::uint32_t>();
        if (m.version < 2 || m.version > 3) throw std::runtime_error("unsupported GGUF version: " + std::to_string(m.version));
        m.tensorCount = r.read<std::uint64_t>();
        const std::uint64_t kvCount = r.read<std::uint64_t>();
        if (kvCount > 1000000ull) throw std::runtime_error("GGUF metadata count unreasonable");
        // Tokens may appear before bos/eos ids — keep a temporary snap for resolution.
        std::vector<std::string> tokenSnap;
        for (std::uint64_t i = 0; i < kvCount; ++i) {
            const std::string key = r.readString();
            const auto type = static_cast<GgufType>(r.read<std::uint32_t>());
            if (key == "general.architecture" && type == GgufType::String) { m.architecture = r.readString(); continue; }
            if (key == "general.name" && type == GgufType::String) { m.modelName = r.readString(); continue; }
            if (key == "tokenizer.chat_template" && type == GgufType::String) { m.chatTemplate = r.readString(); continue; }
            if (key == "tokenizer.ggml.model" && type == GgufType::String) { m.tokenizerModel = r.readString(); continue; }
            if (key == "tokenizer.ggml.bos_token_id") { m.bosToken = readIntegerValue(r, type); continue; }
            if (key == "tokenizer.ggml.eos_token_id") { m.eosToken = readIntegerValue(r, type); continue; }
            if (key == "tokenizer.ggml.add_bos_token") { m.addBos = readBoolValue(r, type); continue; }
            if (key == "tokenizer.ggml.add_eos_token") { m.addEos = readBoolValue(r, type); continue; }
            if (key == "tokenizer.ggml.tokens" && type == GgufType::Array) {
                const auto elementType = static_cast<GgufType>(r.read<std::uint32_t>());
                const std::uint64_t count = r.read<std::uint64_t>();
                if (elementType != GgufType::String || count > 500000ull) {
                    for (std::uint64_t ti = 0; ti < count; ++ti) skipValue(r, elementType);
                    continue;
                }
                tokenSnap.clear();
                tokenSnap.reserve(static_cast<std::size_t>(count));
                for (std::uint64_t ti = 0; ti < count; ++ti) {
                    std::string tok = r.readString();
                    noteVocabMarker(m, tok);
                    tokenSnap.push_back(std::move(tok));
                }
                continue;
            }
            skipValue(r, type);
        }
        resolveSpecialTokenStrings(m, tokenSnap);
        return m;
    }
private:
    static void noteVocabMarker(GgufMetadata& m, const std::string& tok) {
        if (tok == "<|end|>") m.vocabHasEndTag = true;
        else if (tok == "<|im_end|>") m.vocabHasImEnd = true;
        else if (tok == "<|im_start|>") m.vocabHasImStart = true;
        else if (tok == "<|user|>") m.vocabHasUserTag = true;
        else if (tok == "<|assistant|>") m.vocabHasAssistantTag = true;
        else if (tok == "<|system|>") m.vocabHasSystemTag = true;
        else if (tok == "<|tool|>") m.vocabHasToolTag = true;
    }
    static void resolveSpecialTokenStrings(GgufMetadata& m, const std::vector<std::string>& tokens) {
        auto at = [&](std::int64_t id) -> std::string {
            if (id < 0 || static_cast<std::size_t>(id) >= tokens.size()) return {};
            return tokens[static_cast<std::size_t>(id)];
        };
        if (m.bosTokenStr.empty()) m.bosTokenStr = at(m.bosToken);
        if (m.eosTokenStr.empty()) m.eosTokenStr = at(m.eosToken);
        // Llama SPM fallback when ids missing but vocab has the classics.
        if (m.eosTokenStr.empty()) {
            for (const auto& t : tokens) {
                if (t == "</s>") { m.eosTokenStr = t; break; }
            }
        }
        if (m.bosTokenStr.empty()) {
            for (const auto& t : tokens) {
                if (t == "<s>") { m.bosTokenStr = t; break; }
            }
        }
    }
    static std::int64_t readIntegerValue(BinaryReader& r, GgufType type) {
        switch (type) {
        case GgufType::UInt8: return r.read<std::uint8_t>();
        case GgufType::Int8: return r.read<std::int8_t>();
        case GgufType::UInt16: return r.read<std::uint16_t>();
        case GgufType::Int16: return r.read<std::int16_t>();
        case GgufType::UInt32: return r.read<std::uint32_t>();
        case GgufType::Int32: return r.read<std::int32_t>();
        case GgufType::UInt64: {
            const auto value = r.read<std::uint64_t>();
            if (value > static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())) throw std::runtime_error("GGUF integer exceeds int64");
            return static_cast<std::int64_t>(value);
        }
        case GgufType::Int64: return r.read<std::int64_t>();
        default: throw std::runtime_error("GGUF integer key has non-integer type");
        }
    }
    static bool readBoolValue(BinaryReader& r, GgufType type) {
        if (type == GgufType::Bool) return r.read<std::uint8_t>() != 0;
        return readIntegerValue(r, type) != 0;
    }
    static std::uint64_t primitiveSize(GgufType type) {
        switch (type) {
        case GgufType::UInt8: case GgufType::Int8: case GgufType::Bool: return 1;
        case GgufType::UInt16: case GgufType::Int16: return 2;
        case GgufType::UInt32: case GgufType::Int32: case GgufType::Float32: return 4;
        case GgufType::UInt64: case GgufType::Int64: case GgufType::Float64: return 8;
        default: return 0;
        }
    }
    static void skipValue(BinaryReader& r, GgufType type) {
        if (type == GgufType::String) { (void)r.readString(); return; }
        if (type == GgufType::Array) {
            const auto elementType = static_cast<GgufType>(r.read<std::uint32_t>());
            const std::uint64_t count = r.read<std::uint64_t>();
            if (count > 1000000000ull) throw std::runtime_error("GGUF array count unreasonable");
            const auto size = primitiveSize(elementType);
            if (size != 0) {
                if (count > std::numeric_limits<std::uint64_t>::max() / size) throw std::runtime_error("GGUF array byte-size overflow");
                r.skip(count * size); return;
            }
            for (std::uint64_t i = 0; i < count; ++i) skipValue(r, elementType);
            return;
        }
        const auto size = primitiveSize(type);
        if (size == 0) throw std::runtime_error("unknown GGUF metadata type");
        r.skip(size);
    }
};

// =============================================================================
// Chat data / tool schemas
// =============================================================================

enum class Role { System, User, Assistant, Tool };

static const char* roleName(Role role) {
    switch (role) {
    case Role::System: return "system";
    case Role::User: return "user";
    case Role::Assistant: return "assistant";
    case Role::Tool: return "tool";
    }
    return "unknown";
}

struct ChatMessage {
    Role role = Role::User;
    std::string content;
    std::string name;
    std::string toolCallId;
};

struct ToolDefinition {
    std::string name;
    std::string description;
    std::string parametersJson;
};

static std::string toolsAsOpenAIJson(const std::vector<ToolDefinition>& tools) {
    std::ostringstream out;
    out << "[";
    for (std::size_t i = 0; i < tools.size(); ++i) {
        if (i) out << ",";
        out << "{"
            << "\"type\":\"function\","
            << "\"function\":{"
            << "\"name\":" << jsonQuote(tools[i].name) << ","
            << "\"description\":" << jsonQuote(tools[i].description) << ","
            << "\"parameters\":" << tools[i].parametersJson
            << "}"
            << "}";
    }
    out << "]";
    return out.str();
}

static std::string toolInstructionBlock(const std::vector<ToolDefinition>& tools) {
    if (tools.empty()) return {};
    std::ostringstream out;
    out << "You have access to local tools. "
        << "You MUST use tools to inspect and modify files before claiming a fix. "
        << "Do not invent tool results.\n\n"
        << "TOOLS:\n"
        << toolsAsOpenAIJson(tools)
        << "\n\n"
        << "REQUIRED tool format (exact strict JSON arguments; keys and string values MUST be double-quoted):\n"
        << "TOOL_CALL: read_file {\"path\":\"main.c\"}\n"
        << "TOOL_CALL: replace_in_file {\"path\":\"main.c\",\"search\":\"DOES_NOT_EXIST\",\"replace\":\"42\"}\n"
        << "TOOL_CALL: run_command {\"command\":\"cmake --build build\"}\n"
        << "INVALID (rejected, tool will NOT run): {path:main.c, search: \"x\", replace: \"y\"}\n"
        << "If a tool observation reports error=schema_validation, resend the SAME tool with corrected strict JSON.\n"
        << "After a tool observation, emit the next TOOL_CALL or a short final answer. "
        << "Never copy or restate tool observation JSON as your reply.\n"
        << "Do NOT write markdown code fences as a substitute for tools.";
    return out.str();
}

// =============================================================================
// Model-aware ChatTemplate
// =============================================================================

enum class TemplateFamily {
    ChatML, Hermes, Qwen, Llama3, Phi3, Gemma, Mistral, Generic
};

static const char* templateFamilyName(TemplateFamily family) {
    switch (family) {
    case TemplateFamily::ChatML: return "chatml";
    case TemplateFamily::Hermes: return "hermes";
    case TemplateFamily::Qwen: return "qwen";
    case TemplateFamily::Llama3: return "llama3";
    case TemplateFamily::Phi3: return "phi3";
    case TemplateFamily::Gemma: return "gemma";
    case TemplateFamily::Mistral: return "mistral";
    case TemplateFamily::Generic: return "generic";
    }
    return "generic";
}

class ChatTemplate final {
public:
    explicit ChatTemplate(GgufMetadata metadata)
        : metadata_(std::move(metadata)),
          family_(detectFamily(metadata_)),
          contract_(inferTemplateContract(metadata_)) {
        // Isolation stick: RAWRXD_CHAT_FAMILY=phi3|chatml|auto (default auto)
        if (const char* force = std::getenv("RAWRXD_CHAT_FAMILY")) {
            const std::string f = lower(force);
            if (f == "phi3" || f == "zephyr" || f == "tinyllama") {
                family_ = TemplateFamily::Phi3;
            } else if (f == "chatml" || f == "im_start") {
                family_ = TemplateFamily::ChatML;
            } else if (f == "mistral") {
                family_ = TemplateFamily::Mistral;
            } else if (f != "auto" && !f.empty()) {
                std::fprintf(stderr, "[ChatTemplate] unknown RAWRXD_CHAT_FAMILY=%s (keeping auto)\n", force);
            }
        }
        std::printf("[ChatTemplate] family=%s heal=%s stop_bytes=%zu remap_tool=%d eos_id=%lld\n",
                    templateFamilyName(family_),
                    contract_.familyHint.c_str(),
                    contract_.messageStop.size(),
                    contract_.remapToolToUser ? 1 : 0,
                    static_cast<long long>(metadata_.eosToken));
        std::fflush(stdout);
    }

    TemplateFamily family() const { return family_; }
    const GgufMetadata& metadata() const { return metadata_; }
    const TemplateContract& contract() const { return contract_; }

    std::string render(const std::vector<ChatMessage>& messages,
                       const std::vector<ToolDefinition>& tools,
                       bool addGenerationPrompt = true) const {
        switch (family_) {
        case TemplateFamily::Hermes: return renderChatML(messages, tools, addGenerationPrompt, true);
        case TemplateFamily::Qwen: return renderQwen(messages, tools, addGenerationPrompt);
        case TemplateFamily::ChatML: return renderChatML(messages, tools, addGenerationPrompt, false);
        case TemplateFamily::Llama3: return renderLlama3(messages, tools, addGenerationPrompt);
        case TemplateFamily::Phi3: return renderPhi3(messages, tools, addGenerationPrompt);
        case TemplateFamily::Gemma: return renderGemma(messages, tools, addGenerationPrompt);
        case TemplateFamily::Mistral: return renderMistral(messages, tools, addGenerationPrompt);
        case TemplateFamily::Generic: return renderGeneric(messages, tools, addGenerationPrompt);
        }
        throw std::runtime_error("unknown chat template family");
    }

private:
    GgufMetadata metadata_;
    TemplateFamily family_ = TemplateFamily::Generic;
    TemplateContract contract_{};

    static TemplateFamily detectFamily(const GgufMetadata& metadata) {
        const std::string templateLower = lower(metadata.chatTemplate);
        const std::string arch = lower(metadata.architecture);
        const std::string name = lower(metadata.modelName);

        if (templateLower.find("<|im_start|>") != std::string::npos) {
            if (name.find("hermes") != std::string::npos) return TemplateFamily::Hermes;
            return TemplateFamily::ChatML;
        }
        if (arch.find("qwen") != std::string::npos || name.find("qwen") != std::string::npos) return TemplateFamily::Qwen;
        if (templateLower.find("<|start_header_id|>") != std::string::npos ||
            name.find("llama-3") != std::string::npos || name.find("llama 3") != std::string::npos) {
            return TemplateFamily::Llama3;
        }
        // Zephyr / TinyLlama-Chat / Phi-style jinja uses <|user|> + <|assistant|>.
        if (templateLower.find("<|user|>") != std::string::npos &&
            templateLower.find("<|assistant|>") != std::string::npos) {
            return TemplateFamily::Phi3;
        }
        if (arch.find("phi") != std::string::npos) return TemplateFamily::Phi3;
        if (arch.find("gemma") != std::string::npos || templateLower.find("<start_of_turn>") != std::string::npos) {
            return TemplateFamily::Gemma;
        }
        if (arch.find("mistral") != std::string::npos || templateLower.find("[inst]") != std::string::npos) {
            return TemplateFamily::Mistral;
        }
        if (arch == "llama") return TemplateFamily::Mistral;
        return TemplateFamily::Generic;
    }

    static std::vector<ChatMessage> withToolSystemMessage(const std::vector<ChatMessage>& messages,
                                                           const std::vector<ToolDefinition>& tools) {
        std::vector<ChatMessage> result = messages;
        const std::string toolsText = toolInstructionBlock(tools);
        if (toolsText.empty()) return result;
        for (auto& message : result) {
            if (message.role == Role::System) {
                if (!message.content.empty()) message.content += "\n\n";
                message.content += toolsText;
                return result;
            }
        }
        result.insert(result.begin(), ChatMessage{Role::System, toolsText, {}, {}});
        return result;
    }

    // When jinja/vocab never trained <|tool|>, fold tool results into the user role.
    // Do NOT prefix with "TOOL_RESULT:" — TinyLlama copies that label as its next "action".
    std::vector<ChatMessage> applyRoleHealing(std::vector<ChatMessage> messages) const {
        if (!contract_.remapToolToUser) return messages;
        for (auto& message : messages) {
            if (message.role != Role::Tool) continue;
            message.role = Role::User;
            const std::string toolName = message.name.empty() ? "tool" : message.name;
            const std::string callId = message.toolCallId.empty() ? "" : (" id=" + message.toolCallId);
            message.content =
                "Observation from `" + toolName + "`" + callId +
                " (do not echo this block; decide the next TOOL_CALL):\n" +
                message.content;
        }
        return messages;
    }

    std::string renderChatML(const std::vector<ChatMessage>& messages,
                             const std::vector<ToolDefinition>& tools,
                             bool addGenerationPrompt, bool hermes) const {
        const auto expanded = applyRoleHealing(withToolSystemMessage(messages, tools));
        const std::string stop =
            !contract_.messageStop.empty() ? contract_.messageStop : std::string("<|im_end|>");
        std::ostringstream out;
        for (const auto& message : expanded) {
            out << "<|im_start|>" << roleName(message.role) << "\n";
            if (hermes && message.content.find("Observation from `") == 0) {
                out << "<tool_response>\n" << message.content << "\n</tool_response>";
            } else {
                out << message.content;
            }
            out << stop;
            if (stop.empty() || stop.back() != '\n') out << "\n";
        }
        if (addGenerationPrompt) {
            out << (contract_.assistantPrompt.empty() ? "<|im_start|>assistant\n"
                                                       : contract_.assistantPrompt);
        }
        return out.str();
    }

    std::string renderQwen(const std::vector<ChatMessage>& messages,
                           const std::vector<ToolDefinition>& tools,
                           bool addGenerationPrompt) const {
        std::vector<ChatMessage> expanded = messages;
        if (!tools.empty()) {
            std::ostringstream toolSystem;
            toolSystem << "You may call tools.\n" << "<tools>\n";
            for (const auto& tool : tools) {
                toolSystem << "{"
                           << "\"name\":" << jsonQuote(tool.name) << ","
                           << "\"description\":" << jsonQuote(tool.description) << ","
                           << "\"parameters\":" << tool.parametersJson << "}\n";
            }
            toolSystem << "</tools>\n"
                       << "For a tool call emit:\n"
                       << "<tool_call>\n"
                       << "{\"name\":\"tool_name\",\"arguments\":{...}}\n"
                       << "</tool_call>";
            bool inserted = false;
            for (auto& message : expanded) {
                if (message.role == Role::System) {
                    if (!message.content.empty()) message.content += "\n\n";
                    message.content += toolSystem.str();
                    inserted = true; break;
                }
            }
            if (!inserted) expanded.insert(expanded.begin(), ChatMessage{Role::System, toolSystem.str(), {}, {}});
        }
        expanded = applyRoleHealing(std::move(expanded));
        std::ostringstream out;
        for (const auto& message : expanded) {
            out << "<|im_start|>" << roleName(message.role) << "\n" << message.content << "<|im_end|>\n";
        }
        if (addGenerationPrompt) out << "<|im_start|>assistant\n";
        return out.str();
    }

    std::string renderLlama3(const std::vector<ChatMessage>& messages,
                             const std::vector<ToolDefinition>& tools,
                             bool addGenerationPrompt) const {
        const auto expanded = applyRoleHealing(withToolSystemMessage(messages, tools));
        std::ostringstream out;
        out << "<|begin_of_text|>";
        for (const auto& message : expanded) {
            out << "<|start_header_id|>" << roleName(message.role) << "<|end_header_id|>\n\n"
                << message.content << "<|eot_id|>";
        }
        if (addGenerationPrompt) out << "<|start_header_id|>assistant<|end_header_id|>\n\n";
        return out.str();
    }

    std::string renderPhi3(const std::vector<ChatMessage>& messages,
                           const std::vector<ToolDefinition>& tools,
                           bool addGenerationPrompt) const {
        // Contract-driven: messageStop comes from eos_token / healed <|end|>.
        const auto expanded = applyRoleHealing(withToolSystemMessage(messages, tools));
        const std::string& stop = contract_.messageStop;
        std::ostringstream out;
        for (const auto& message : expanded) {
            const char* role =
                message.role == Role::System ? "system" :
                message.role == Role::Assistant ? "assistant" : "user";
            out << "<|" << role << "|>\n" << message.content << stop;
        }
        if (addGenerationPrompt) {
            out << (contract_.assistantPrompt.empty() ? "<|assistant|>\n"
                                                      : contract_.assistantPrompt);
        }
        return out.str();
    }

    std::string renderGemma(const std::vector<ChatMessage>& messages,
                            const std::vector<ToolDefinition>& tools,
                            bool addGenerationPrompt) const {
        const auto expanded = applyRoleHealing(withToolSystemMessage(messages, tools));
        std::ostringstream out;
        out << "<bos>";
        for (const auto& message : expanded) {
            const char* role = message.role == Role::Assistant ? "model" : "user";
            out << "<start_of_turn>" << role << "\n";
            if (message.role == Role::System) out << "[SYSTEM]\n";
            out << message.content << "<end_of_turn>\n";
        }
        if (addGenerationPrompt) out << "<start_of_turn>model\n";
        return out.str();
    }

    std::string renderMistral(const std::vector<ChatMessage>& messages,
                              const std::vector<ToolDefinition>& tools,
                              bool addGenerationPrompt) const {
        const auto expanded = applyRoleHealing(withToolSystemMessage(messages, tools));
        std::ostringstream out;
        std::string pendingSystem;
        const std::string stop = contract_.messageStop.empty() ? "</s>" : contract_.messageStop;
        for (const auto& message : expanded) {
            if (message.role == Role::System) { pendingSystem = message.content; continue; }
            if (message.role == Role::User) {
                out << "<s>[INST] ";
                if (!pendingSystem.empty()) { out << pendingSystem << "\n\n"; pendingSystem.clear(); }
                out << message.content << " [/INST]";
            } else if (message.role == Role::Assistant) {
                out << " " << message.content << stop;
            }
        }
        (void)addGenerationPrompt;
        return out.str();
    }

    std::string renderGeneric(const std::vector<ChatMessage>& messages,
                              const std::vector<ToolDefinition>& tools,
                              bool addGenerationPrompt) const {
        const auto expanded = applyRoleHealing(withToolSystemMessage(messages, tools));
        std::ostringstream out;
        for (const auto& message : expanded) {
            out << roleName(message.role) << ": " << message.content << "\n";
        }
        if (addGenerationPrompt) out << "assistant: ";
        return out.str();
    }
};

// =============================================================================
// Compile-time Deep2 adapter — zero external dependencies
// =============================================================================

template <typename T>
concept ConstructibleFromString = std::is_constructible_v<T, const std::string&>;

template <typename T>
concept ConstructibleFromCString = std::is_constructible_v<T, const char*>;

template <typename T>
concept DefaultConstructible = std::is_default_constructible_v<T>;

template <typename T>
concept HasLoadModelString = requires(T& engine, const std::string& path) { engine.loadModel(path); };

template <typename T>
concept HasLoadModelCString = requires(T& engine, const char* path) { engine.loadModel(path); };

template <typename T>
concept HasLoadString = requires(T& engine, const std::string& path) { engine.load(path); };

template <typename T>
concept HasLoadCString = requires(T& engine, const char* path) { engine.load(path); };

using StringChunkCallback = std::function<void(const std::string&)>;
using ViewChunkCallback = std::function<void(std::string_view)>;
using BoolStringChunkCallback = std::function<bool(const std::string&)>;

template <typename T>
concept HasGenerateStreamStringCallback = requires(T& engine, const std::string& prompt, int maxTokens, StringChunkCallback callback) {
    engine.generateStream(prompt, maxTokens, callback);
};

template <typename T>
concept HasGenerateStreamViewCallback = requires(T& engine, const std::string& prompt, int maxTokens, ViewChunkCallback callback) {
    engine.generateStream(prompt, maxTokens, callback);
};

template <typename T>
concept HasGenerateStreamBoolCallback = requires(T& engine, const std::string& prompt, int maxTokens, BoolStringChunkCallback callback) {
    engine.generateStream(prompt, maxTokens, callback);
};

template <typename T>
concept HasGenerateString = requires(T& engine, const std::string& prompt, int maxTokens) {
    { engine.generate(prompt, maxTokens) } -> std::convertible_to<std::string>;
};

template <typename T>
concept HasGenerateText = requires(T& engine, const std::string& prompt, size_t maxTokens) {
    { engine.generateText(prompt, maxTokens) } -> std::convertible_to<std::string>;
};

template <typename T>
concept HasSetTemperature = requires(T& engine, float value) {
    engine.setTemperature(value);
};

template <typename T>
concept HasSetTopP = requires(T& engine, float value) {
    engine.setTopP(value);
};

template <typename T>
concept HasSetSampling = requires(T& engine, float temperature, float topP) {
    engine.setSampling(temperature, topP);
};

static_assert(
    HasGenerateStreamStringCallback<Deep2> ||
    HasGenerateStreamViewCallback<Deep2> ||
    HasGenerateStreamBoolCallback<Deep2> ||
    HasGenerateString<Deep2> ||
    HasGenerateText<Deep2>,
    "Deep2Engine exposes no supported REAL generation API. "
    "Add/adapt generateStream(prompt,maxTokens,callback) or "
    "generate(prompt,maxTokens) or generateText(prompt,maxTokens). Placeholder inference is forbidden.");

template <typename ReturnType>
static bool loadReturnSucceeded(ReturnType&& result) {
    using R = std::remove_cvref_t<ReturnType>;
    if constexpr (std::is_same_v<R, bool>) return result;
    else if constexpr (std::is_integral_v<R>) return result != 0;
    else return true;
}

template <typename Engine>
static bool invokeLoad(Engine& engine, const std::string& path) {
    if constexpr (HasLoadModelString<Engine>) {
        using R = decltype(engine.loadModel(path));
        if constexpr (std::is_void_v<R>) { engine.loadModel(path); return true; }
        else return loadReturnSucceeded(engine.loadModel(path));
    }
    else if constexpr (HasLoadModelCString<Engine>) {
        using R = decltype(engine.loadModel(path.c_str()));
        if constexpr (std::is_void_v<R>) { engine.loadModel(path.c_str()); return true; }
        else return loadReturnSucceeded(engine.loadModel(path.c_str()));
    }
    else if constexpr (HasLoadString<Engine>) {
        using R = decltype(engine.load(path));
        if constexpr (std::is_void_v<R>) { engine.load(path); return true; }
        else return loadReturnSucceeded(engine.load(path));
    }
    else if constexpr (HasLoadCString<Engine>) {
        using R = decltype(engine.load(path.c_str()));
        if constexpr (std::is_void_v<R>) { engine.load(path.c_str()); return true; }
        else return loadReturnSucceeded(engine.load(path.c_str()));
    }
    else return true;
}

class Deep2Adapter final {
public:
    explicit Deep2Adapter(const fs::path& modelPath)
        : engine_(createEngine<Deep2>(modelPath.string())) {
        if (!engine_) throw std::runtime_error("Deep2 construction failed");
    }

    bool trueStreaming() const {
        return HasGenerateStreamStringCallback<Deep2> ||
               HasGenerateStreamViewCallback<Deep2> ||
               HasGenerateStreamBoolCallback<Deep2>;
    }

    bool hasRealGeneration() const {
        return HasGenerateStreamStringCallback<Deep2> ||
               HasGenerateStreamViewCallback<Deep2> ||
               HasGenerateStreamBoolCallback<Deep2> ||
               HasGenerateString<Deep2> ||
               HasGenerateText<Deep2>;
    }

    bool applySampling(float temperature, float topP) {
        if (!engine_) return false;
        return applySamplingImpl(*engine_, temperature, topP);
    }

    std::string generate(const std::string& prompt, int maxTokens,
                         const std::function<bool(std::string_view)>& onChunk) {
        if (!engine_) throw std::runtime_error("Deep2 engine is unavailable");
        return generateImpl(*engine_, prompt, maxTokens, onChunk);
    }

private:
    std::unique_ptr<Deep2> engine_;

    template <typename Engine>
    static bool applySamplingImpl(Engine& engine, float temperature, float topP) {
        if constexpr (HasSetSampling<Engine>) {
            engine.setSampling(temperature, topP);
            return true;
        } else {
            bool applied = false;
            if constexpr (HasSetTemperature<Engine>) {
                engine.setTemperature(temperature);
                applied = true;
            }
            if constexpr (HasSetTopP<Engine>) {
                engine.setTopP(topP);
                applied = true;
            }
            return applied;
        }
    }

    template <typename Engine>
    static std::unique_ptr<Engine> createEngine(const std::string& path) {
        if constexpr (ConstructibleFromString<Engine>) {
            return std::make_unique<Engine>(path);
        }
        else if constexpr (ConstructibleFromCString<Engine>) {
            return std::make_unique<Engine>(path.c_str());
        }
        else if constexpr (DefaultConstructible<Engine>) {
            static_assert(
                HasLoadModelString<Engine> || HasLoadModelCString<Engine> ||
                HasLoadString<Engine> || HasLoadCString<Engine>,
                "Default-constructed Deep2Engine must expose a real model-load method.");
            auto engine = std::make_unique<Engine>();
            if (!invokeLoad(*engine, path)) throw std::runtime_error("Deep2 rejected model: " + path);
            return engine;
        }
        else {
            static_assert(std::is_default_constructible_v<Engine>,
                "Deep2Engine is not constructible by any supported model-load shape.");
            return {};
        }
    }

    template <typename Engine>
    static std::string generateImpl(Engine& engine, const std::string& prompt, int maxTokens,
                                    const std::function<bool(std::string_view)>& onChunk) {
        std::string collected;
        auto deliver = [&](std::string_view chunk) -> bool {
            collected.append(chunk.data(), chunk.size());
            if (onChunk) return onChunk(chunk);
            return true;
        };

        if constexpr (HasGenerateStreamStringCallback<Engine>) {
            StringChunkCallback callback = [&](const std::string& chunk) { (void)deliver(chunk); };
            engine.generateStream(prompt, maxTokens, callback);
            return collected;
        }
        else if constexpr (HasGenerateStreamViewCallback<Engine>) {
            ViewChunkCallback callback = [&](std::string_view chunk) { (void)deliver(chunk); };
            engine.generateStream(prompt, maxTokens, callback);
            return collected;
        }
        else if constexpr (HasGenerateStreamBoolCallback<Engine>) {
            BoolStringChunkCallback callback = [&](const std::string& chunk) { return deliver(chunk); };
            engine.generateStream(prompt, maxTokens, callback);
            return collected;
        }
        else if constexpr (HasGenerateString<Engine>) {
            const std::string result = engine.generate(prompt, maxTokens);
            (void)deliver(result);
            return collected;
        }
        else if constexpr (HasGenerateText<Engine>) {
            const std::string result = engine.generateText(prompt, static_cast<size_t>(maxTokens));
            (void)deliver(result);
            return collected;
        }
        else {
            static_assert(HasGenerateText<Engine>, "No real Deep2 generation method available.");
            return {};
        }
    }
};

// =============================================================================
// Tool-call parser
// =============================================================================

struct ToolCall {
    std::string id;
    std::string name;
    std::string argumentsJson;
};

static std::optional<std::string> extractTagged(std::string_view text, std::string_view open, std::string_view close) {
    const auto begin = text.find(open);
    if (begin == std::string_view::npos) return std::nullopt;
    const auto contentStart = begin + open.size();
    const auto end = text.find(close, contentStart);
    if (end == std::string_view::npos) return std::nullopt;
    return std::string(text.substr(contentStart, end - contentStart));
}

static std::vector<std::string> extractJsonObjects(std::string_view text) {
    std::vector<std::string> objects;
    bool inString = false;
    bool escaped = false;
    int depth = 0;
    std::size_t start = 0;
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (inString) {
            if (escaped) escaped = false;
            else if (c == '\\') escaped = true;
            else if (c == '"') inString = false;
            continue;
        }
        if (c == '"') { inString = true; continue; }
        if (c == '{') { if (depth == 0) start = i; ++depth; }
        else if (c == '}') { if (depth > 0) { --depth; if (depth == 0) objects.emplace_back(text.substr(start, i - start + 1)); } }
    }
    return objects;
}

class ToolCallParser final {
public:
    static std::vector<ToolCall> parse(const std::string& response) {
        std::vector<std::string> candidates;
        static constexpr std::array<std::pair<std::string_view, std::string_view>, 4> wrappers = {{
            {"<tool_call>", "</tool_call>"},
            {"<|tool_call|>", "<|end_tool_call|>"},
            {"<toolcall>", "</toolcall>"},
            {"<function_call>", "</function_call>"}
        }};
        for (const auto& [open, close] : wrappers) {
            std::size_t offset = 0;
            while (offset < response.size()) {
                const auto b = response.find(open, offset);
                if (b == std::string::npos) break;
                const auto content = b + open.size();
                const auto e = response.find(close, content);
                if (e == std::string::npos) break;
                candidates.emplace_back(response.substr(content, e - content));
                offset = e + close.size();
            }
        }
        const auto rawObjects = extractJsonObjects(response);
        candidates.insert(candidates.end(), rawObjects.begin(), rawObjects.end());
        std::vector<ToolCall> calls;
        std::set<std::string> dedupe;
        // RawrXD IDE grammar: TOOL_CALL: name {json}
        {
            std::size_t pos = 0;
            while (pos < response.size()) {
                const auto toolPos = response.find("TOOL_CALL:", pos);
                if (toolPos == std::string::npos) break;
                auto cursor = toolPos + std::strlen("TOOL_CALL:");
                while (cursor < response.size() && std::isspace(static_cast<unsigned char>(response[cursor]))) ++cursor;
                const auto nameBegin = cursor;
                while (cursor < response.size() &&
                       (std::isalnum(static_cast<unsigned char>(response[cursor])) ||
                        response[cursor] == '_' || response[cursor] == '-')) {
                    ++cursor;
                }
                if (cursor == nameBegin) { pos = toolPos + 1; continue; }
                const std::string name = response.substr(nameBegin, cursor - nameBegin);
                while (cursor < response.size() && std::isspace(static_cast<unsigned char>(response[cursor]))) ++cursor;
                if (cursor >= response.size() || response[cursor] != '{') { pos = toolPos + 1; continue; }
                int depth = 0;
                const auto jsonBegin = cursor;
                for (; cursor < response.size(); ++cursor) {
                    if (response[cursor] == '{') ++depth;
                    else if (response[cursor] == '}') {
                        --depth;
                        if (depth == 0) { ++cursor; break; }
                    }
                }
                if (depth != 0) { pos = toolPos + 1; continue; }
                const std::string args = response.substr(jsonBegin, cursor - jsonBegin);
                const std::string fingerprint = name + "\n" + args;
                if (dedupe.insert(fingerprint).second) {
                    calls.push_back(ToolCall{
                        "call_" + std::to_string(calls.size() + 1), name, args});
                }
                pos = cursor;
            }
        }
        for (const auto& candidate : candidates) parseCandidate(candidate, calls, dedupe);
        return calls;
    }

private:
    static void parseCandidate(const std::string& candidate, std::vector<ToolCall>& out, std::set<std::string>& dedupe) {
        const auto toolCallsRaw = jsonRawField(candidate, "tool_calls");
        if (toolCallsRaw && !toolCallsRaw->empty() && toolCallsRaw->front() == '[') {
            const auto objects = extractJsonObjects(*toolCallsRaw);
            for (const auto& item : objects) {
                const auto functionRaw = jsonRawField(item, "function");
                if (functionRaw) addObjectCall(*functionRaw, jsonStringField(item, "id").value_or(""), out, dedupe);
                else addObjectCall(item, jsonStringField(item, "id").value_or(""), out, dedupe);
            }
            return;
        }
        const auto functionRaw = jsonRawField(candidate, "function");
        if (functionRaw) {
            addObjectCall(*functionRaw, jsonStringField(candidate, "id").value_or(""), out, dedupe);
            return;
        }
        addObjectCall(candidate, {}, out, dedupe);
    }

    static void addObjectCall(const std::string& object, const std::string& id,
                               std::vector<ToolCall>& out, std::set<std::string>& dedupe) {
        const auto name = jsonStringField(object, "name");
        if (!name || name->empty()) return;
        std::string arguments = jsonRawField(object, "arguments").value_or("{}");
        if (arguments.size() >= 2 && arguments.front() == '"' && arguments.back() == '"') {
            arguments = unescapeJsonString(arguments);
        }
        const std::string fingerprint = *name + "\n" + arguments;
        if (!dedupe.insert(fingerprint).second) return;
        out.push_back(ToolCall{id.empty() ? "call_" + std::to_string(out.size() + 1) : id, *name, std::move(arguments)});
    }
};

// =============================================================================
// Tool result / workspace sandbox
// =============================================================================

struct ToolResult {
    bool success = false;
    std::string tool;
    std::string output;
    int exitCode = 0;
    std::string error;                 // e.g. "schema_validation" (empty = runtime/tool result)
    std::vector<std::string> details;
    bool dispatched = false;           // true only if handler executed

    static ToolResult schemaFailure(const std::string& toolName,
                                    std::vector<std::string> detailsIn) {
        ToolResult r;
        r.success = false;
        r.tool = toolName;
        r.exitCode = -3;
        r.error = "schema_validation";
        r.details = std::move(detailsIn);
        r.dispatched = false;
        // Compact message for the model (avoid blowing TinyLlama context).
        std::ostringstream msg;
        msg << "error=schema_validation dispatched=false. "
            << "Fix arguments to strict JSON with quoted keys, e.g. "
            << "TOOL_CALL: " << toolName << " {\"path\":\"main.c\"}. Details:";
        for (const auto& d : r.details) msg << " [" << d << "]";
        r.output = msg.str();
        return r;
    }

    std::string toJson() const {
        std::ostringstream out;
        out << "{" << "\"ok\":" << (success ? "true" : "false") << ","
            << "\"tool\":" << jsonQuote(tool) << ","
            << "\"exit_code\":" << exitCode << ","
            << "\"dispatched\":" << (dispatched ? "true" : "false") << ","
            << "\"output\":" << jsonQuote(output);
        if (!error.empty()) {
            out << ",\"error\":" << jsonQuote(error) << ",\"details\":[";
            for (std::size_t i = 0; i < details.size(); ++i) {
                if (i) out << ",";
                out << jsonQuote(details[i]);
            }
            out << "]";
        }
        out << "}";
        return out.str();
    }
};

// AGENT-TOOL-SCHEMA-002: strict JSON object (quoted keys). Bare-key TinyLlama dialect
// is repaired explicitly via tryRepairBareKeyJsonObject (logged) before this gate.
static bool isStrictJsonObject(std::string_view raw) {
    const std::string trimmed = trim(std::string(raw));
    if (trimmed.empty() || trimmed.front() != '{') return false;
    const auto whole = scanBalancedJson(trimmed, 0);
    if (!whole) return false;
    std::size_t after = skipWs(trimmed, whole->end);
    if (after != trimmed.size()) return false;

    std::size_t i = skipWs(trimmed, 1);
    if (i < trimmed.size() && trimmed[i] == '}') return true;
    while (i < trimmed.size()) {
        i = skipWs(trimmed, i);
        if (i >= trimmed.size() || trimmed[i] != '"') return false; // bare key / non-JSON
        const auto key = scanJsonString(trimmed, i);
        if (!key) return false;
        i = skipWs(trimmed, key->end);
        if (i >= trimmed.size() || trimmed[i] != ':') return false;
        ++i;
        const auto value = scanJsonValue(trimmed, i);
        if (!value) return false;
        i = skipWs(trimmed, value->end);
        if (i >= trimmed.size()) return false;
        if (trimmed[i] == ',') { ++i; continue; }
        if (trimmed[i] == '}') return skipWs(trimmed, i + 1) == trimmed.size();
        return false;
    }
    return false;
}

// TinyLlama often emits {path:main.c, search: "x", replace: "y"} — quote bare keys/values.
// Returns strict JSON on success; nullopt if irreparable (fail-closed at schema gate).
static std::optional<std::string> tryRepairBareKeyJsonObject(std::string_view raw) {
    const std::string trimmed = trim(std::string(raw));
    if (trimmed.empty() || trimmed.front() != '{') return std::nullopt;
    if (isStrictJsonObject(trimmed)) return trimmed;

    auto isKeyStart = [](unsigned char c) { return std::isalpha(c) || c == '_'; };
    auto isKeyCont = [](unsigned char c) { return std::isalnum(c) || c == '_'; };
    auto isJsonLiteral = [](std::string_view v) {
        if (v == "true" || v == "false" || v == "null") return true;
        if (v.empty()) return false;
        std::size_t i = 0;
        if (v[0] == '-' || v[0] == '+') ++i;
        if (i >= v.size() || !std::isdigit(static_cast<unsigned char>(v[i]))) return false;
        bool sawDot = false;
        for (; i < v.size(); ++i) {
            const unsigned char c = static_cast<unsigned char>(v[i]);
            if (std::isdigit(c)) continue;
            if (c == '.' && !sawDot) { sawDot = true; continue; }
            return false;
        }
        return true;
    };

    std::ostringstream out;
    out << '{';
    std::size_t i = skipWs(trimmed, 1);
    bool first = true;
    while (i < trimmed.size()) {
        i = skipWs(trimmed, i);
        if (i < trimmed.size() && trimmed[i] == '}') {
            out << '}';
            return skipWs(trimmed, i + 1) == trimmed.size()
                ? std::optional<std::string>(out.str())
                : std::nullopt;
        }
        if (!first) {
            if (i >= trimmed.size() || trimmed[i] != ',') return std::nullopt;
            out << ',';
            ++i;
            i = skipWs(trimmed, i);
        }
        first = false;

        std::string key;
        if (i < trimmed.size() && trimmed[i] == '"') {
            const auto keySlice = scanJsonString(trimmed, i);
            if (!keySlice) return std::nullopt;
            key = unescapeJsonString(trimmed.substr(keySlice->begin, keySlice->end - keySlice->begin));
            i = keySlice->end;
        } else if (i < trimmed.size() && isKeyStart(static_cast<unsigned char>(trimmed[i]))) {
            const std::size_t begin = i;
            while (i < trimmed.size() && isKeyCont(static_cast<unsigned char>(trimmed[i]))) ++i;
            key = std::string(trimmed.substr(begin, i - begin));
        } else {
            return std::nullopt;
        }
        i = skipWs(trimmed, i);
        if (i >= trimmed.size() || trimmed[i] != ':') return std::nullopt;
        ++i;
        i = skipWs(trimmed, i);
        if (i >= trimmed.size()) return std::nullopt;

        out << jsonQuote(key) << ':';
        if (trimmed[i] == '"') {
            const auto vs = scanJsonString(trimmed, i);
            if (!vs) return std::nullopt;
            out << trimmed.substr(vs->begin, vs->end - vs->begin);
            i = vs->end;
        } else if (trimmed[i] == '{' || trimmed[i] == '[') {
            const auto vs = scanBalancedJson(trimmed, i);
            if (!vs) return std::nullopt;
            const auto nested = trimmed.substr(vs->begin, vs->end - vs->begin);
            if (trimmed[i] == '{') {
                const auto repairedNested = tryRepairBareKeyJsonObject(nested);
                out << (repairedNested ? *repairedNested : nested);
            } else {
                out << nested;
            }
            i = vs->end;
        } else {
            const auto vs = scanJsonValue(trimmed, i);
            if (!vs) return std::nullopt;
            const auto lit = trimmed.substr(vs->begin, vs->end - vs->begin);
            if (isJsonLiteral(lit)) out << lit;
            else out << jsonQuote(lit);
            i = vs->end;
        }
    }
    return std::nullopt;
}

static std::vector<std::string> schemaRequiredKeys(const std::string& parametersJson) {
    std::vector<std::string> keys;
    const auto pos = parametersJson.find("\"required\"");
    if (pos == std::string::npos) return keys;
    const auto bracket = parametersJson.find('[', pos);
    if (bracket == std::string::npos) return keys;
    const auto end = parametersJson.find(']', bracket);
    if (end == std::string::npos) return keys;
    const std::string arr = parametersJson.substr(bracket, end - bracket + 1);
    std::size_t i = 0;
    while (i < arr.size()) {
        const auto q = arr.find('"', i);
        if (q == std::string::npos) break;
        const auto slice = scanJsonString(arr, q);
        if (!slice) break;
        keys.push_back(unescapeJsonString(arr.substr(slice->begin, slice->end - slice->begin)));
        i = slice->end;
    }
    return keys;
}

struct ArgSchemaCheck {
    bool ok = false;
    std::vector<std::string> details;
};

static ArgSchemaCheck validateToolArguments(const ToolDefinition& def, const std::string& argumentsJson) {
    ArgSchemaCheck check;
    if (!isStrictJsonObject(argumentsJson)) {
        check.details.push_back("arguments must be valid JSON");
        check.details.push_back(
            "use double-quoted keys and string values, e.g. {\"path\":\"main.c\"}");
        return check;
    }
    for (const auto& key : schemaRequiredKeys(def.parametersJson)) {
        if (!jsonStringField(argumentsJson, key) && !jsonRawField(argumentsJson, key)) {
            check.details.push_back("required argument missing: " + key);
        } else if (jsonRawField(argumentsJson, key) && !jsonStringField(argumentsJson, key)) {
            // present but not a JSON string — for string-typed required keys this is invalid
            // Heuristic: if schema properties mark it as string, require string.
            const std::string needle = "\"" + key + "\":{\"type\":\"string\"}";
            const std::string needleSpaced = "\"" + key + "\": {\"type\": \"string\"}";
            if (def.parametersJson.find(needle) != std::string::npos ||
                def.parametersJson.find(needleSpaced) != std::string::npos ||
                def.parametersJson.find("\"" + key + "\":{\"type\":\"string\"") != std::string::npos) {
                if (!jsonStringField(argumentsJson, key)) {
                    check.details.push_back("required string argument missing: " + key);
                }
            }
        }
    }
    // replace_in_file: path required as string; search/replace (or aliases) required as strings.
    if (def.name == "replace_in_file") {
        if (!jsonStringField(argumentsJson, "path")) {
            check.details.push_back("required string argument missing: path");
        }
        const bool hasSearch = jsonStringField(argumentsJson, "search").has_value() ||
                               jsonStringField(argumentsJson, "old_string").has_value();
        const bool hasReplace = jsonStringField(argumentsJson, "replace").has_value() ||
                                jsonStringField(argumentsJson, "new_string").has_value();
        if (!hasSearch) check.details.push_back("required string argument missing: search (or old_string)");
        if (!hasReplace) check.details.push_back("required string argument missing: replace (or new_string)");
    }
    if (def.name == "run_command" && !jsonStringField(argumentsJson, "command")) {
        check.details.push_back("required string argument missing: command");
    }
    if (def.name == "write_file") {
        if (!jsonStringField(argumentsJson, "path"))
            check.details.push_back("required string argument missing: path");
        if (!jsonStringField(argumentsJson, "content"))
            check.details.push_back("required string argument missing: content");
    }
    if (def.name == "read_file" && !jsonStringField(argumentsJson, "path")) {
        check.details.push_back("required string argument missing: path");
    }
    // Dedupe details
    std::set<std::string> seen;
    std::vector<std::string> unique;
    for (const auto& d : check.details) {
        if (seen.insert(d).second) unique.push_back(d);
    }
    check.details = std::move(unique);
    check.ok = check.details.empty();
    return check;
}

class WorkspaceSandbox final {
public:
    explicit WorkspaceSandbox(fs::path root) {
        std::error_code ec;
        root_ = fs::weakly_canonical(fs::absolute(std::move(root)), ec);
        if (ec || root_.empty() || !fs::exists(root_)) throw std::runtime_error("invalid workspace root");
    }
    const fs::path& root() const { return root_; }
    fs::path resolveExisting(const std::string& userPath) const {
        const fs::path candidate = absoluteCandidate(userPath);
        std::error_code ec;
        const fs::path canonical = fs::weakly_canonical(candidate, ec);
        if (ec) throw std::runtime_error("path cannot be resolved: " + userPath);
        enforceInside(canonical);
        return canonical;
    }
    fs::path resolveForWrite(const std::string& userPath) const {
        const fs::path candidate = absoluteCandidate(userPath);
        fs::path parent = candidate.parent_path();
        if (parent.empty()) parent = root_;
        std::error_code ec;
        const fs::path canonicalParent = fs::weakly_canonical(parent, ec);
        if (ec) throw std::runtime_error("parent path cannot be resolved: " + parent.string());
        enforceInside(canonicalParent);
        const fs::path finalPath = canonicalParent / candidate.filename();
        enforceInside(finalPath);
        return finalPath;
    }
private:
    fs::path root_;
    fs::path absoluteCandidate(const std::string& userPath) const {
        fs::path p = fs::path(userPath);
        if (p.empty()) return root_;
        if (!p.is_absolute()) p = root_ / p;
        return p;
    }
    void enforceInside(const fs::path& candidate) const {
        const auto rootString = lower(root_.lexically_normal().generic_string());
        const auto candidateString = lower(candidate.lexically_normal().generic_string());
        if (candidateString == rootString) return;
        std::string prefix = rootString;
        if (!prefix.empty() && prefix.back() != '/') prefix.push_back('/');
        if (!startsWith(candidateString, prefix)) throw std::runtime_error("path escapes workspace: " + candidate.string());
    }
};

// =============================================================================
// Process execution with Windows timeout/job containment
// =============================================================================

struct ProcessResult {
    int exitCode = -1;
    bool timedOut = false;
    std::string output;
};

#ifdef _WIN32

static ProcessResult runProcessWindows(const fs::path& workingDirectory,
                                        const std::wstring& commandLine,
                                        std::chrono::milliseconds timeout) {
    SECURITY_ATTRIBUTES sa{}; sa.nLength = sizeof(sa); sa.bInheritHandle = TRUE;
    HANDLE readPipe = nullptr; HANDLE writePipe = nullptr;
    if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) throw std::runtime_error("CreatePipe failed");
    SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);
    STARTUPINFOW startup{}; startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = writePipe; startup.hStdError = writePipe;
    startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    PROCESS_INFORMATION process{};
    std::vector<wchar_t> mutableCommand(commandLine.begin(), commandLine.end());
    mutableCommand.push_back(L'\0');
    const std::wstring cwd = workingDirectory.wstring();
    const BOOL created = CreateProcessW(nullptr, mutableCommand.data(), nullptr, nullptr, TRUE,
                                         CREATE_NO_WINDOW, nullptr, cwd.c_str(), &startup, &process);
    CloseHandle(writePipe); writePipe = nullptr;
    if (!created) { CloseHandle(readPipe); throw std::runtime_error("CreateProcessW failed"); }
    HANDLE job = CreateJobObjectW(nullptr, nullptr);
    if (job) {
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(job, JobObjectExtendedLimitInformation, &limits, sizeof(limits));
        AssignProcessToJobObject(job, process.hProcess);
    }
    ProcessResult result;
    std::atomic<bool> readerDone{false};
    std::thread reader([&]() {
        std::array<char, 4096> buffer{};
        for (;;) {
            DWORD read = 0;
            const BOOL ok = ReadFile(readPipe, buffer.data(), static_cast<DWORD>(buffer.size()), &read, nullptr);
            if (!ok || read == 0) break;
            result.output.append(buffer.data(), read);
        }
        readerDone = true;
    });
    const DWORD wait = WaitForSingleObject(process.hProcess,
        timeout.count() > static_cast<std::int64_t>(std::numeric_limits<DWORD>::max()) ? INFINITE : static_cast<DWORD>(timeout.count()));
    if (wait == WAIT_TIMEOUT) {
        result.timedOut = true;
        if (job) TerminateJobObject(job, 124);
        else TerminateProcess(process.hProcess, 124);
        WaitForSingleObject(process.hProcess, 5000);
    }
    DWORD exitCode = 1;
    GetExitCodeProcess(process.hProcess, &exitCode);
    result.exitCode = static_cast<int>(exitCode);
    CloseHandle(process.hThread); CloseHandle(process.hProcess);
    if (job) CloseHandle(job);
    CloseHandle(readPipe);
    if (reader.joinable()) reader.join();
    return result;
}

static std::wstring widenUtf8(const std::string& utf8) {
    if (utf8.empty()) return {};
    const int length = MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), nullptr, 0);
    if (length <= 0) throw std::runtime_error("UTF-8 to UTF-16 conversion failed");
    std::wstring wide;
    wide.resize(static_cast<std::size_t>(length));
    MultiByteToWideChar(CP_UTF8, 0, utf8.data(), static_cast<int>(utf8.size()), wide.data(), length);
    return wide;
}

#endif

static ProcessResult runProcess(const fs::path& workingDirectory,
                                 const std::string& command,
                                 std::chrono::milliseconds timeout) {
#ifdef _WIN32
    const std::wstring wrapped = L"cmd.exe /d /s /c \"" + widenUtf8(command) + L"\"";
    return runProcessWindows(workingDirectory, wrapped, timeout);
#else
    (void)timeout;
    ProcessResult result;
    const std::string full = "cd " + jsonQuote(workingDirectory.string()) + " && " + command + " 2>&1";
    FILE* pipe = popen(full.c_str(), "r");
    if (!pipe) throw std::runtime_error("popen failed");
    std::array<char, 4096> buffer{};
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe)) result.output += buffer.data();
    result.exitCode = pclose(pipe);
    return result;
#endif
}

// =============================================================================
// Core local coding tools
// =============================================================================

class ToolRegistry final {
public:
    explicit ToolRegistry(WorkspaceSandbox sandbox) : sandbox_(std::move(sandbox)) { registerCoreTools(); }

    std::vector<ToolDefinition> definitions() const {
        std::vector<ToolDefinition> result;
        result.reserve(definitions_.size());
        for (const auto& [name, definition] : definitions_) result.push_back(definition);
        std::sort(result.begin(), result.end(), [](const ToolDefinition& a, const ToolDefinition& b) { return a.name < b.name; });
        return result;
    }

    ToolResult dispatch(const ToolCall& call) {
        const auto it = handlers_.find(call.name);
        if (it == handlers_.end()) {
            ToolResult r{false, call.name, "unknown tool: " + call.name, -1};
            r.error = "unknown_tool";
            r.dispatched = false;
            return r;
        }
        const auto defIt = definitions_.find(call.name);
        if (defIt == definitions_.end()) {
            return ToolResult::schemaFailure(call.name, {"tool definition missing"});
        }
        // Fail-closed on irreparable args; TinyLlama bare-key dialect is repaired + logged.
        std::string argsJson = call.argumentsJson;
        const bool strictEnv = []() {
            const char* v = std::getenv("RAWRXD_TOOL_ARGS_STRICT");
            return v && v[0] == '1' && v[1] == '\0';
        }();
        if (!isStrictJsonObject(argsJson) && !strictEnv) {
            if (auto repaired = tryRepairBareKeyJsonObject(argsJson)) {
                std::printf("[TOOL_SCHEMA] REPAIR tool=%s bare_keys->strict\n", call.name.c_str());
                std::fflush(stdout);
                argsJson = std::move(*repaired);
            }
        }
        const ArgSchemaCheck check = validateToolArguments(defIt->second, argsJson);
        if (!check.ok) {
            std::printf("[TOOL_SCHEMA] REJECT tool=%s dispatched=0 details=%zu\n",
                        call.name.c_str(), check.details.size());
            std::fflush(stdout);
            return ToolResult::schemaFailure(call.name, check.details);
        }
        try {
            ToolResult result = it->second(argsJson);
            result.dispatched = true;
            if (result.tool.empty()) result.tool = call.name;
            std::printf("[TOOL_SCHEMA] ACCEPT tool=%s dispatched=1 ok=%d\n",
                        call.name.c_str(), result.success ? 1 : 0);
            std::fflush(stdout);
            return result;
        } catch (const std::exception& ex) {
            ToolResult r{false, call.name, ex.what(), -1};
            r.dispatched = true; // handler entered; runtime failure after gate
            r.error = "tool_runtime";
            return r;
        }
    }

private:
    using Handler = std::function<ToolResult(const std::string&)>;
    WorkspaceSandbox sandbox_;
    std::unordered_map<std::string, ToolDefinition> definitions_;
    std::unordered_map<std::string, Handler> handlers_;
    std::set<std::string> allowedExecutables_ {
        "cmake", "ninja", "ctest", "git", "powershell", "pwsh", "cmd",
        "cl", "link", "msbuild", "devenv", "python", "python3"
    };

    static std::string requiredString(const std::string& arguments, const std::string& key) {
        const auto value = jsonStringField(arguments, key);
        if (!value) throw std::runtime_error("missing string argument: " + key);
        return *value;
    }

    void addTool(ToolDefinition definition, Handler handler) {
        handlers_[definition.name] = std::move(handler);
        definitions_[definition.name] = std::move(definition);
    }

    void registerCoreTools() {
        addTool({"read_file", "Read a UTF-8/text file inside the workspace.",
                 R"({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]})"},
            [&](const std::string& args) {
                const auto path = sandbox_.resolveExisting(requiredString(args, "path"));
                if (!fs::is_regular_file(path)) throw std::runtime_error("not a regular file: " + path.string());
                return ToolResult{true, "read_file", readWholeFile(path, 10ull * 1024ull * 1024ull), 0};
            });

        addTool({"list_directory", "List files/directories inside the workspace.",
                 R"({"type":"object","properties":{"path":{"type":"string"}}})"},
            [&](const std::string& args) {
                const auto pathArg = jsonStringField(args, "path").value_or(".");
                const auto path = sandbox_.resolveExisting(pathArg);
                if (!fs::is_directory(path)) throw std::runtime_error("not a directory: " + path.string());
                std::vector<fs::directory_entry> entries;
                for (const auto& entry : fs::directory_iterator(path)) entries.push_back(entry);
                std::sort(entries.begin(), entries.end(), [](const auto& a, const auto& b) {
                    return lower(a.path().filename().string()) < lower(b.path().filename().string());
                });
                std::ostringstream out;
                for (const auto& entry : entries) {
                    out << (entry.is_directory() ? "[D] " : "[F] ") << entry.path().filename().string();
                    if (entry.is_regular_file()) {
                        std::error_code ec;
                        const auto size = entry.file_size(ec);
                        if (!ec) out << " (" << size << " bytes)";
                    }
                    out << "\n";
                }
                return ToolResult{true, "list_directory", out.str(), 0};
            });

        addTool({"write_file", "Write a complete file inside the workspace. Existing files are backed up before replacement.",
                 R"({"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}},"required":["path","content"]})"},
            [&](const std::string& args) {
                const std::string pathArg = requiredString(args, "path");
                const std::string content = requiredString(args, "content");
                if (content.size() > 10ull * 1024ull * 1024ull) throw std::runtime_error("write exceeds 10 MiB limit");
                const auto path = sandbox_.resolveForWrite(pathArg);
                fs::create_directories(path.parent_path());
                if (fs::exists(path)) {
                    const fs::path backup = path.string() + ".rawrxd.bak";
                    std::error_code ec;
                    fs::copy_file(path, backup, fs::copy_options::overwrite_existing, ec);
                    if (ec) throw std::runtime_error("backup failed: " + ec.message());
                }
                writeWholeFile(path, content);
                return ToolResult{true, "write_file", "wrote " + std::to_string(content.size()) + " bytes to " + path.string(), 0};
            });

        addTool({"replace_in_file", "Replace exact text inside one workspace file.",
                 R"({"type":"object","properties":{"path":{"type":"string"},"search":{"type":"string"},"replace":{"type":"string"},"old_string":{"type":"string"},"new_string":{"type":"string"},"replace_all":{"type":"boolean"}},"required":["path"]})"},
            [&](const std::string& args) {
                const auto path = sandbox_.resolveExisting(requiredString(args, "path"));
                const std::string search = jsonStringField(args, "search")
                    .value_or(jsonStringField(args, "old_string").value_or(""));
                const std::string replacement = jsonStringField(args, "replace")
                    .value_or(jsonStringField(args, "new_string").value_or(""));
                if (search.empty()) throw std::runtime_error("search/old_string must not be empty");
                const bool replaceAll = jsonRawField(args, "replace_all").value_or("false") == "true";
                std::string content = readWholeFile(path, 10ull * 1024ull * 1024ull);
                std::vector<std::size_t> matches;
                for (std::size_t pos = 0; (pos = content.find(search, pos)) != std::string::npos;) {
                    matches.push_back(pos); pos += search.size();
                }
                if (matches.empty()) throw std::runtime_error("search text not found");
                if (!replaceAll && matches.size() != 1) throw std::runtime_error("search text appears " + std::to_string(matches.size()) + " times; refine it or set replace_all=true");
                const fs::path backup = path.string() + ".rawrxd.bak";
                std::error_code ec;
                fs::copy_file(path, backup, fs::copy_options::overwrite_existing, ec);
                if (ec) throw std::runtime_error("backup failed: " + ec.message());
                std::size_t replaced = 0; std::size_t pos = 0;
                while ((pos = content.find(search, pos)) != std::string::npos) {
                    content.replace(pos, search.size(), replacement);
                    pos += replacement.size(); ++replaced;
                    if (!replaceAll) break;
                }
                writeWholeFile(path, content);
                return ToolResult{true, "replace_in_file", "replaced " + std::to_string(replaced) + " occurrence(s) in " + path.string(), 0};
            });

        addTool({"search_text", "Recursively search workspace text files for a literal string.",
                 R"({"type":"object","properties":{"query":{"type":"string"},"path":{"type":"string"},"max_results":{"type":"integer"}},"required":["query"]})"},
            [&](const std::string& args) {
                const std::string query = requiredString(args, "query");
                if (query.empty()) throw std::runtime_error("query must not be empty");
                const auto base = sandbox_.resolveExisting(jsonStringField(args, "path").value_or("."));
                const std::int64_t maxResults = std::clamp<std::int64_t>(jsonIntegerField(args, "max_results").value_or(100), 1, 1000);
                static const std::set<std::string> extensions = {
                    ".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".inl",
                    ".asm", ".s", ".ps1", ".bat", ".cmd", ".cmake", ".txt", ".md",
                    ".json", ".xml", ".yaml", ".yml", ".py", ".js", ".ts", ".tsx", ".jsx"
                };
                std::ostringstream out;
                std::int64_t resultCount = 0;
                for (const auto& entry : fs::recursive_directory_iterator(base, fs::directory_options::skip_permission_denied)) {
                    if (resultCount >= maxResults) break;
                    if (!entry.is_regular_file()) continue;
                    const auto ext = lower(entry.path().extension().string());
                    if (!extensions.count(ext)) continue;
                    std::error_code ec;
                    const auto size = entry.file_size(ec);
                    if (ec || size > 4ull * 1024ull * 1024ull) continue;
                    std::ifstream input(entry.path());
                    if (!input) continue;
                    std::string line; std::size_t lineNo = 0;
                    while (std::getline(input, line)) {
                        ++lineNo;
                        if (line.find(query) != std::string::npos) {
                            out << fs::relative(entry.path(), sandbox_.root()).string() << ":" << lineNo << ": " << line << "\n";
                            ++resultCount;
                            if (resultCount >= maxResults) break;
                        }
                    }
                }
                return ToolResult{true, "search_text", out.str(), 0};
            });

        addTool({"run_command", "Run an allow-listed local build/test/version-control command inside the workspace with a timeout.",
                 R"({"type":"object","properties":{"command":{"type":"string"},"timeout_ms":{"type":"integer"}},"required":["command"]})"},
            [&](const std::string& args) {
                const std::string command = requiredString(args, "command");
                const auto timeoutMs = std::clamp<std::int64_t>(jsonIntegerField(args, "timeout_ms").value_or(120000), 1000, 600000);
                validateCommand(command);
                const auto result = runProcess(sandbox_.root(), command, std::chrono::milliseconds(timeoutMs));
                std::ostringstream out;
                if (result.timedOut) out << "[TIMEOUT]\n";
                out << result.output;
                return ToolResult{!result.timedOut && result.exitCode == 0, "run_command", out.str(), result.exitCode};
            });

        addTool({"git_status", "Show git status for the current workspace.", R"({"type":"object","properties":{}})"},
            [&](const std::string&) {
                const auto result = runProcess(sandbox_.root(), "git status --short --branch", std::chrono::milliseconds(30000));
                return ToolResult{result.exitCode == 0, "git_status", result.output, result.exitCode};
            });

        addTool({"git_diff", "Show the current git diff for the workspace.",
                 R"({"type":"object","properties":{"cached":{"type":"boolean"}}})"},
            [&](const std::string& args) {
                const bool cached = jsonRawField(args, "cached").value_or("false") == "true";
                const auto result = runProcess(sandbox_.root(), cached ? "git diff --cached" : "git diff", std::chrono::milliseconds(30000));
                return ToolResult{result.exitCode == 0, "git_diff", result.output, result.exitCode};
            });
    }

    void validateCommand(const std::string& command) const {
        std::string trimmed = trim(command);
        if (trimmed.empty()) throw std::runtime_error("command must not be empty");
        static constexpr std::array<std::string_view, 8> forbidden = {"&&", "||", ";", "\n", "\r", ">", "<", "`"};
        for (const auto token : forbidden) {
            if (trimmed.find(token) != std::string::npos) throw std::runtime_error("shell chaining/redirection is not allowed");
        }
        std::size_t end = 0;
        while (end < trimmed.size() && !std::isspace(static_cast<unsigned char>(trimmed[end]))) ++end;
        std::string executable = lower(trimmed.substr(0, end));
        if (executable.size() >= 2 && executable.front() == '"' && executable.back() == '"') {
            executable = executable.substr(1, executable.size() - 2);
        }
        executable = fs::path(executable).stem().string();
        if (!allowedExecutables_.count(executable)) throw std::runtime_error("executable is not allow-listed: " + executable);
    }
};

// =============================================================================
// NativeInferenceClient + ChatStreamer
// =============================================================================

struct StreamEvent {
    enum class Kind { Text, ToolCall, Done, Error };
    Kind kind = Kind::Text;
    std::string text;
    std::optional<ToolCall> toolCall;
};

using StreamCallback = std::function<bool(const StreamEvent&)>;

class NativeInferenceClient final {
public:
    explicit NativeInferenceClient(fs::path modelPath)
        : modelPath_(fs::absolute(std::move(modelPath))),
          metadata_(GgufMetadataReader::read(modelPath_)),
          chatTemplate_(metadata_),
          deep2_(modelPath_) {}

    const GgufMetadata& metadata() const { return metadata_; }
    TemplateFamily templateFamily() const { return chatTemplate_.family(); }
    bool trueStreaming() const { return deep2_.trueStreaming(); }
    bool applySampling(float temperature, float topP) {
        return deep2_.applySampling(temperature, topP);
    }

    // TOKENIZER-PARITY / AGENT-FIRST-TOKEN: dump exact bytes at Agentic→Deep2 boundary
    static void dumpPromptForTokenizerCert(const std::string& prompt) {
        const bool tokCert = []() {
            const char* e = std::getenv("RAWRXD_TOKENIZER_CERT");
            return e && e[0] == '1';
        }();
        const bool firstTok = []() {
            const char* e = std::getenv("RAWRXD_AGENT_FIRST_TOKEN");
            return e && e[0] == '1';
        }();
        if (!tokCert && !firstTok) return;

        const char* dir = firstTok
            ? "F:\\~dev\\rawrxd\\evidence\\AGENT_E2E_002b\\AGENT_FIRST_TOKEN_001"
            : "F:\\~dev\\rawrxd\\evidence\\AGENT_E2E_002b\\TOKENIZER_PARITY_001";
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        {
            std::ofstream f(std::string(dir) + "\\rendered_prompt.bin", std::ios::binary);
            f.write(prompt.data(), static_cast<std::streamsize>(prompt.size()));
        }
        {
            std::ofstream f(std::string(dir) + "\\rendered_prompt.txt", std::ios::binary);
            f << prompt;
        }
        std::printf("[AGENT] PROMPT_RENDERED bytes=%zu\n", prompt.size());
        std::fflush(stdout);
        std::fprintf(stderr,
                     "[TOKENIZER_CERT] rendered_prompt_bytes=%zu dir=%s\n",
                     prompt.size(), dir);
        std::fflush(stderr);
    }

    std::string ChatSync(const std::vector<ChatMessage>& messages,
                          const std::vector<ToolDefinition>& tools,
                          int maxTokens) {
        std::printf("[AGENT] MODEL_READY chat_family=%s\n",
                    templateFamilyName(chatTemplate_.family()));
        std::fflush(stdout);
        const std::string prompt = chatTemplate_.render(messages, tools, true);
        dumpPromptForTokenizerCert(prompt);
        int genTokens = maxTokens;
        if (const char* ft = std::getenv("RAWRXD_AGENT_FIRST_TOKEN"); ft && ft[0] == '1') {
            genTokens = 1;
        }
        return deep2_.generate(prompt, genTokens, {});
    }

    std::string ChatStream(const std::vector<ChatMessage>& messages,
                            const std::vector<ToolDefinition>& tools,
                            int maxTokens,
                            const StreamCallback& callback) {
        std::printf("[AGENT] MODEL_READY chat_family=%s\n",
                    templateFamilyName(chatTemplate_.family()));
        std::fflush(stdout);
        const std::string prompt = chatTemplate_.render(messages, tools, true);
        dumpPromptForTokenizerCert(prompt);
        int genTokens = maxTokens;
        if (const char* ft = std::getenv("RAWRXD_AGENT_FIRST_TOKEN"); ft && ft[0] == '1') {
            genTokens = 1;
        }
        std::string full; bool cancelled = false;
        auto onChunk = [&](std::string_view chunk) -> bool {
            if (cancelled) return false;
            full.append(chunk.data(), chunk.size());
            if (callback) {
                const bool keepGoing = callback(StreamEvent{StreamEvent::Kind::Text, std::string(chunk), std::nullopt});
                if (!keepGoing) { cancelled = true; return false; }
            }
            return true;
        };
        try {
            full = deep2_.generate(prompt, genTokens, onChunk);
            if (!cancelled && callback) {
                const auto calls = ToolCallParser::parse(full);
                for (const auto& call : calls) {
                    callback(StreamEvent{StreamEvent::Kind::ToolCall, {}, call});
                }
                callback(StreamEvent{StreamEvent::Kind::Done, {}, std::nullopt});
            }
            return full;
        }
        catch (const std::exception& ex) {
            if (callback) callback(StreamEvent{StreamEvent::Kind::Error, ex.what(), std::nullopt});
            throw;
        }
    }

private:
    fs::path modelPath_;
    GgufMetadata metadata_;
    ChatTemplate chatTemplate_;
    Deep2Adapter deep2_;
};

// =============================================================================
// Agent transcript
// =============================================================================

struct TranscriptStep {
    int step = 0;
    std::string timestamp;
    std::string modelResponse;
    std::vector<ToolCall> toolCalls;
    std::vector<ToolResult> toolResults;
    std::uint64_t inferenceMs = 0;
    std::uint64_t toolMs = 0;
};

class AgentTranscript final {
public:
    void add(TranscriptStep step) { steps_.push_back(std::move(step)); }
    std::string toJson() const {
        std::ostringstream out;
        out << "{" << "\"steps\":[";
        for (std::size_t i = 0; i < steps_.size(); ++i) {
            if (i) out << ",";
            const auto& step = steps_[i];
            out << "{" << "\"step\":" << step.step << ","
                << "\"timestamp\":" << jsonQuote(step.timestamp) << ","
                << "\"inference_ms\":" << step.inferenceMs << ","
                << "\"tool_ms\":" << step.toolMs << ","
                << "\"model_response\":" << jsonQuote(step.modelResponse) << ","
                << "\"tool_calls\":[";
            for (std::size_t j = 0; j < step.toolCalls.size(); ++j) {
                if (j) out << ",";
                const auto& tc = step.toolCalls[j];
                // Always emit arguments as a JSON string when not a strict object,
                // so the transcript itself remains valid JSON.
                out << "{" << "\"id\":" << jsonQuote(tc.id) << ","
                    << "\"name\":" << jsonQuote(tc.name) << ","
                    << "\"arguments\":";
                if (isStrictJsonObject(tc.argumentsJson)) out << tc.argumentsJson;
                else out << jsonQuote(tc.argumentsJson);
                out << "}";
            }
            out << "]," << "\"tool_results\":[";
            for (std::size_t j = 0; j < step.toolResults.size(); ++j) {
                if (j) out << ",";
                out << step.toolResults[j].toJson();
            }
            out << "]" << "}";
        }
        out << "]" << "}";
        return out.str();
    }
private:
    std::vector<TranscriptStep> steps_;
};

// =============================================================================
// Bounded sovereign agent loop
// =============================================================================

struct AgentConfig {
    int maxSteps = 16;
    int maxTokensPerTurn = 2048;
    int verifierMaxTokens = 192;
    std::uint32_t repeatMaxAttempts = 6;
    bool streamToConsole = true;
    bool saveTranscript = true;
    bool verifyFinalAnswers = true;
};

struct AgentResult {
    bool success = false;
    bool hitStepLimit = false;
    int steps = 0;
    std::string answer;
    std::string error;
};

class SovereignAgent final {
public:
    SovereignAgent(NativeInferenceClient& inference, ToolRegistry& tools, AgentConfig config)
        : inference_(inference), tools_(tools), config_(config) {}

    AgentResult execute(const std::string& task) {
        hexmag::RepeatSession repeat(hexmag::requestHash(task), config_.repeatMaxAttempts);
        if (!repeat.valid()) {
            return AgentResult{false, false, 0, {},
                "HEXMAG repeat tuner initialization/invariant failure"};
        }

        std::vector<ChatMessage> messages;
        messages.push_back({Role::System, systemPrompt() + "\n\n" + repeat.directive(), {}, {}});
        messages.push_back({Role::User, task, {}, {}});
        const auto toolDefinitions = tools_.definitions();
        std::set<std::string> previousCallFingerprints;
        AgentTranscript transcript;

        for (int step = 1; step <= config_.maxSteps; ++step) {
            const bool nativeSampling =
                inference_.applySampling(repeat.temperature(), repeat.topP());

            std::printf(
                "[HEXMAG] step=%d attempt=%u generation_id=%llu fingerprint=%llu "
                "strategy=%s specialist=%s temp=%.3f top_p=%.3f native_sampling=%d "
                "blocking_passes=%u weight_delta=%u\n",
                step,
                repeat.attempt(),
                static_cast<unsigned long long>(repeat.generationId()),
                static_cast<unsigned long long>(repeat.fingerprint()),
                hexmag::strategyName(repeat.profile().strategy),
                hexmag::specialistName(repeat.profile().specialist),
                static_cast<double>(repeat.temperature()),
                static_cast<double>(repeat.topP()),
                nativeSampling ? 1 : 0,
                repeat.profile().blockingPasses,
                hexmag::HexMag_Tuner_WeightDelta());
            std::fflush(stdout);

            TranscriptStep record;
            record.step = step;
            record.timestamp = isoTimeNow();
            std::string response;
            const auto inferStart = std::chrono::steady_clock::now();
            try {
                // With the verifier enabled, do not emit candidate text before it clears
                // all blocking passes. This makes unsupported_claim_emission fail-closed.
                response = inference_.ChatStream(
                    messages, toolDefinitions, config_.maxTokensPerTurn,
                    [&](const StreamEvent& event) {
                        if (event.kind == StreamEvent::Kind::Text &&
                            config_.streamToConsole &&
                            !config_.verifyFinalAnswers) {
                            std::cout << event.text << std::flush;
                        }
                        return true;
                    });
            }
            catch (const std::exception& ex) {
                persistTranscript(transcript);
                return AgentResult{false, false, step, {}, ex.what()};
            }
            catch (...) {
                persistTranscript(transcript);
                return AgentResult{false, false, step, {},
                    "non-std exception during inference"};
            }
            const auto inferEnd = std::chrono::steady_clock::now();
            record.inferenceMs = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    inferEnd - inferStart).count());
            record.modelResponse = response;
            if (config_.streamToConsole && !config_.verifyFinalAnswers)
                std::cout << "\n";

            const auto calls = ToolCallParser::parse(response);
            record.toolCalls = calls;

            if (calls.empty()) {
                if (trim(response).empty()) {
                    transcript.add(std::move(record));
                    persistTranscript(transcript);
                    if (!advanceRepeat(
                            repeat,
                            hexmag::HX_FAIL_WRONG | hexmag::HX_FAIL_STAGNATION,
                            messages,
                            "model produced an empty response")) {
                        return exhaustedResult(step);
                    }
                    continue;
                }

                if (config_.verifyFinalAnswers) {
                    const Verification verdict =
                        verifyFinalCandidate(task, response, transcript, repeat);
                    if (!verdict.pass) {
                        transcript.add(std::move(record));
                        persistTranscript(transcript);
                        const std::uint32_t mask =
                            verdict.failureMask == 0
                                ? static_cast<std::uint32_t>(hexmag::HX_FAIL_WRONG)
                                : verdict.failureMask;
                        if (!advanceRepeat(repeat, mask, messages, verdict.reason)) {
                            return exhaustedResult(step);
                        }
                        continue;
                    }
                }

                transcript.add(std::move(record));
                persistTranscript(transcript);
                if (config_.streamToConsole && config_.verifyFinalAnswers) {
                    std::cout << response << "\n";
                }
                return AgentResult{true, false, step, response, {}};
            }

            messages.push_back({Role::Assistant, response, {}, {}});
            const auto toolStart = std::chrono::steady_clock::now();
            std::uint32_t failureMask = 0;

            for (const auto& call : calls) {
                const std::string fingerprint =
                    call.name + "\n" + call.argumentsJson;
                if (!previousCallFingerprints.insert(fingerprint).second) {
                    const ToolResult loopResult{
                        false,
                        call.name,
                        "identical tool call repeated; change strategy before retrying",
                        -2};
                    record.toolResults.push_back(loopResult);
                    messages.push_back(
                        {Role::Tool, loopResult.toJson(), call.name, call.id});
                    failureMask |=
                        hexmag::HX_FAIL_STAGNATION | hexmag::HX_FAIL_WRONG;
                    continue;
                }

                ToolResult result = tools_.dispatch(call);
                record.toolResults.push_back(result);
                messages.push_back(
                    {Role::Tool, result.toJson(), call.name, call.id});

                if (!result.success) {
                    failureMask |= hexmag::HX_FAIL_WRONG;
                    if (result.error == "schema_validation" ||
                        result.error == "unknown_tool" ||
                        result.exitCode != 0) {
                        failureMask |= hexmag::HX_FAIL_TEST;
                    }
                    const std::string evidence = lower(result.output + " " + result.error);
                    if (evidence.find("contradict") != std::string::npos) {
                        failureMask |= hexmag::HX_FAIL_CONTRADICTION;
                    }
                    if (evidence.find("counterexample") != std::string::npos) {
                        failureMask |= hexmag::HX_FAIL_COUNTEREXAMPLE;
                    }
                }
            }

            const auto toolEnd = std::chrono::steady_clock::now();
            record.toolMs = static_cast<std::uint64_t>(
                std::chrono::duration_cast<std::chrono::milliseconds>(
                    toolEnd - toolStart).count());
            transcript.add(std::move(record));
            persistTranscript(transcript);

            if (failureMask != 0) {
                if (!advanceRepeat(
                        repeat,
                        failureMask,
                        messages,
                        "tool/build/test evidence rejected the current generation")) {
                    return exhaustedResult(step);
                }
            }

            std::printf("[AGENT_STEP] completed=%d next_inference=%d\n",
                        step, step < config_.maxSteps ? 1 : 0);
            std::fflush(stdout);
        }

        persistTranscript(transcript);
        return AgentResult{
            false, true, config_.maxSteps, {},
            "agent reached configured step limit"};
    }

private:
    struct Verification {
        bool pass = false;
        std::uint32_t failureMask = 0;
        std::string reason;
    };

    NativeInferenceClient& inference_;
    ToolRegistry& tools_;
    AgentConfig config_;

    static std::string systemPrompt() {
        return "You are RawrXD's local sovereign coding agent. "
               "You operate only on the provided workspace and local tools. "
               "Complete the user's task end-to-end. "
               "Inspect before editing. "
               "Tool arguments MUST be strict JSON with double-quoted keys and string values. "
               "If a tool observation has error=schema_validation, correct the JSON and retry; "
               "the previous call did not execute. "
               "Never echo tool observation JSON; always respond with a TOOL_CALL or a final answer. "
               "Use exact tool results; never claim a build or test passed unless "
               "you actually ran it and observed a successful result. "
               "When a command fails, inspect the failure, modify the source if "
               "appropriate, and retry with a changed strategy. "
               "Prefer narrow, correct edits over unrelated changes. "
               "Do not repeatedly issue an identical failed tool call. "
               "Unsupported factual completion claims are forbidden. "
               "When finished, provide the concise final result and the validation "
               "you performed.";
    }

    static std::uint32_t classifyVerifierFailure(std::string_view verdictText) {
        const std::string v = lower(std::string(verdictText));
        std::uint32_t mask = 0;
        if (v.find("missing_info") != std::string::npos ||
            v.find("missing information") != std::string::npos ||
            v.find("insufficient_information") != std::string::npos) {
            mask |= hexmag::HX_FAIL_MISSING_INFO;
        }
        if (v.find("unsupported") != std::string::npos ||
            v.find("halluc") != std::string::npos ||
            v.find("assumption") != std::string::npos) {
            mask |= hexmag::HX_FAIL_UNSUPPORTED;
        }
        if (v.find("contradiction") != std::string::npos ||
            v.find("contradict") != std::string::npos) {
            mask |= hexmag::HX_FAIL_CONTRADICTION;
        }
        if (v.find("counterexample") != std::string::npos) {
            mask |= hexmag::HX_FAIL_COUNTEREXAMPLE;
        }
        if (v.find("test") != std::string::npos ||
            v.find("compile") != std::string::npos ||
            v.find("runtime") != std::string::npos) {
            mask |= hexmag::HX_FAIL_TEST;
        }
        if (v.find("stagnation") != std::string::npos ||
            v.find("duplicate") != std::string::npos ||
            v.find("repeat") != std::string::npos) {
            mask |= hexmag::HX_FAIL_STAGNATION;
        }
        if (mask == 0) mask = hexmag::HX_FAIL_WRONG;
        return mask | hexmag::HX_FAIL_WRONG;
    }

    Verification verifyFinalCandidate(
        const std::string& task,
        const std::string& candidate,
        const AgentTranscript& transcript,
        hexmag::RepeatSession& repeat) {

        Verification aggregate;
        aggregate.pass = true;
        std::ostringstream reasons;

        std::string evidence = transcript.toJson();
        constexpr std::size_t kMaxEvidenceBytes = 24 * 1024;
        if (evidence.size() > kMaxEvidenceBytes) {
            evidence =
                "[...older transcript truncated...]" +
                evidence.substr(evidence.size() - kMaxEvidenceBytes);
        }

        const std::uint32_t passes =
            std::max<std::uint32_t>(1, repeat.profile().blockingPasses);

        // Evidence verification must be conservative. Use native deterministic
        // controls when Deep2 exposes setters; otherwise the verifier prompt still
        // forbids confidence-as-evidence, but the log truthfully reports no native setter.
        const bool verifierNativeSampling = inference_.applySampling(0.0f, 0.80f);
        std::printf("[HEXMAG_VERIFY] passes=%u native_sampling=%d\n",
                    passes, verifierNativeSampling ? 1 : 0);

        for (std::uint32_t pass = 0; pass < passes; ++pass) {
            std::vector<ChatMessage> verifierMessages;
            verifierMessages.push_back({
                Role::System,
                "You are RawrXD's blocking correctness verifier. "
                "Judge only against the supplied task and observed transcript/tool evidence. "
                "Confidence is not evidence. Unsupported claims fail. "
                "Return exactly one line: "
                "VERDICT=PASS or VERDICT=FAIL KIND=<WRONG|UNSUPPORTED|TEST|"
                "CONTRADICTION|COUNTEREXAMPLE|STAGNATION|MISSING_INFO> REASON=<short reason>.",
                {}, {}
            });

            std::ostringstream prompt;
            prompt << "PASS_INDEX=" << pass + 1 << "/" << passes << "\n"
                   << "GENERATION_ID=" << repeat.generationId() << "\n"
                   << "TASK:\n" << task << "\n\n"
                   << "CANDIDATE_FINAL:\n" << candidate << "\n\n"
                   << "OBSERVED_TRANSCRIPT:\n" << evidence;
            verifierMessages.push_back({Role::User, prompt.str(), {}, {}});

            std::string verdict;
            try {
                verdict = inference_.ChatSync(
                    verifierMessages, {}, config_.verifierMaxTokens);
            } catch (const std::exception& ex) {
                aggregate.pass = false;
                aggregate.failureMask |=
                    hexmag::HX_FAIL_WRONG | hexmag::HX_FAIL_UNSUPPORTED;
                reasons << "verifier_exception=" << ex.what() << "; ";
                continue;
            }

            const std::string normalized = lower(trim(verdict));
            const bool explicitPass =
                normalized.find("verdict=pass") != std::string::npos;
            const bool explicitFail =
                normalized.find("verdict=fail") != std::string::npos;

            std::printf("[HEXMAG_VERIFY] pass=%u explicit_pass=%d explicit_fail=%d\n",
                        pass + 1, explicitPass ? 1 : 0, explicitFail ? 1 : 0);

            if (!explicitPass || explicitFail) {
                aggregate.pass = false;
                aggregate.failureMask |= classifyVerifierFailure(verdict);
                reasons << "pass" << pass + 1 << "=" << trim(verdict) << "; ";
            }
        }

        // Restore active generation sampling after deterministic verifier passes.
        inference_.applySampling(repeat.temperature(), repeat.topP());

        if (aggregate.pass) {
            aggregate.reason = "all blocking verifier passes accepted candidate";
        } else {
            aggregate.reason = reasons.str();
            if (aggregate.reason.empty())
                aggregate.reason = "blocking verifier rejected candidate";
        }
        return aggregate;
    }

    bool advanceRepeat(
        hexmag::RepeatSession& repeat,
        std::uint32_t failureMask,
        std::vector<ChatMessage>& messages,
        const std::string& reason) {

        const auto oldGeneration = repeat.generationId();
        if (!repeat.advance(failureMask)) return false;

        // Mutate the active system contract in-place. generation_id and mutation_nonce
        // change the actual prompt bytes, so even a greedy backend does not receive the
        // identical generation request after a rejection.
        messages.front().content =
            systemPrompt() + "\n\n" + repeat.directive();

        std::ostringstream observation;
        observation << "Previous generation " << oldGeneration
                    << " was rejected. failure_mask=0x"
                    << std::hex << failureMask << std::dec
                    << ". " << reason
                    << "\nDo not repeat the rejected answer. Continue using the new "
                       "HEXMAG_REPEAT_PROFILE.";
        messages.push_back({Role::User, observation.str(), {}, {}});

        std::printf(
            "[HEXMAG_MUTATE] old_generation_id=%llu new_generation_id=%llu "
            "attempt=%u strategy=%s failure_mask=0x%X\n",
            static_cast<unsigned long long>(oldGeneration),
            static_cast<unsigned long long>(repeat.generationId()),
            repeat.attempt(),
            hexmag::strategyName(repeat.profile().strategy),
            failureMask);
        std::fflush(stdout);
        return true;
    }

    static AgentResult exhaustedResult(int step) {
        return AgentResult{
            false,
            false,
            step,
            {},
            "INSUFFICIENT_INFORMATION: HexMag repeat budget exhausted without a "
            "verified answer; fake success is forbidden"};
    }

    void persistTranscript(const AgentTranscript& transcript) const {
        if (!config_.saveTranscript) return;
        try {
            const fs::path path =
                fs::current_path() / "RAWRXD_AGENT_TRANSCRIPT.json";
            writeWholeFile(path, transcript.toJson());
        }
        catch (...) {}
    }
};

// =============================================================================
// CLI
// =============================================================================

struct CliOptions {
    fs::path model;
    fs::path workspace;
    std::string task;
    int maxSteps = 16;
    int maxTokens = 2048;
    bool noStream = false;
    bool toolSchemaCert = false;  // AGENT-TOOL-SCHEMA-002 lanes A/B (no model inference)
    fs::path schemaCertOut;       // optional evidence dir for dumps
};

static CliOptions parseCli(int argc, char** argv) {
    CliOptions options;
    auto value = [&](int& index, const std::string& argument) -> std::string {
        ++index;
        if (index >= argc) throw std::runtime_error("missing value for " + argument);
        return argv[index];
    };
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--model") options.model = value(i, arg);
        else if (arg == "--workspace") options.workspace = value(i, arg);
        else if (arg == "--task") options.task = value(i, arg);
        else if (arg == "--max-steps") {
            const auto text = value(i, arg);
            int parsed = 0;
            const auto result = std::from_chars(text.data(), text.data() + text.size(), parsed);
            if (result.ec != std::errc{} || parsed < 1 || parsed > 128) throw std::runtime_error("invalid --max-steps");
            options.maxSteps = parsed;
        }
        else if (arg == "--max-tokens") {
            const auto text = value(i, arg);
            int parsed = 0;
            const auto result = std::from_chars(text.data(), text.data() + text.size(), parsed);
            if (result.ec != std::errc{} || parsed < 1 || parsed > 65536) throw std::runtime_error("invalid --max-tokens");
            options.maxTokens = parsed;
        }
        else if (arg == "--no-stream") options.noStream = true;
        else if (arg == "--tool-schema-cert") options.toolSchemaCert = true;
        else if (arg == "--schema-cert-out") options.schemaCertOut = value(i, arg);
        else if (arg == "--help" || arg == "-h") {
            std::cout << "RawrXD-Agentic.exe --model path --workspace DIR [--task \"...\"]\n"
                         "  [--max-steps N] [--max-tokens N] [--no-stream]\n"
                         "  [--tool-schema-cert] [--schema-cert-out DIR]\n";
            std::exit(EXIT_SUCCESS);
        }
        else throw std::runtime_error("unknown argument: " + arg);
    }
    if (!options.toolSchemaCert && options.model.empty())
        throw std::runtime_error("--model is required (unless --tool-schema-cert)");
    if (options.workspace.empty()) options.workspace = fs::current_path();
    return options;
}

// AGENT-TOOL-SCHEMA-002: model-independent lanes:
//   A = irreparable / strict-mode reject (SCHEMA_VALID=false ⇒ DISPATCHED=false)
//   R = TinyLlama bare-key dialect repaired then accepted
//   B = already-strict JSON accepted
static int runToolSchemaCert(const CliOptions& cli) {
    WorkspaceSandbox sandbox(cli.workspace);
    ToolRegistry tools(sandbox);
    const fs::path outDir = cli.schemaCertOut.empty()
        ? (fs::path("F:/~dev/rawrxd/evidence/AGENT_TOOL_SCHEMA_002"))
        : cli.schemaCertOut;
    std::error_code ec;
    fs::create_directories(outDir, ec);

    struct Case {
        const char* lane;
        const char* raw;
        bool expectAccept;
        bool expectDispatch;
        bool forceStrict; // disable bare-key repair for this case
    };
    const Case cases[] = {
        // Lane A: fail-closed (strict) — bare keys must NOT dispatch
        {"A", "TOOL_CALL: replace_in_file {path:main.c, search: \"DOES_NOT_EXIST\", replace: \"42\"}", false, false, true},
        {"A", "TOOL_CALL: run_command {command: \"cmake --build build\"}", false, false, true},
        {"A", "TOOL_CALL: read_file {path:\"main.c\"}", false, false, true}, // mixed / irreparable-ish under strict
        // Lane R: repair enabled — same bare-key dialect becomes SCHEMA_VALID + dispatched
        {"R", "TOOL_CALL: replace_in_file {path:main.c, search: \"DOES_NOT_EXIST\", replace: \"42\"}", true, true, false},
        {"R", "TOOL_CALL: read_file {path:main.c}", true, true, false},
        // Lane B: already strict
        {"B", "TOOL_CALL: replace_in_file {\"path\":\"main.c\",\"search\":\"DOES_NOT_EXIST\",\"replace\":\"42\"}", true, true, false},
        {"B", "TOOL_CALL: read_file {\"path\":\"main.c\"}", true, true, false},
        {"B", "TOOL_CALL: run_command {\"command\":\"cmake --build build\"}", true, true, false},
    };

    bool laneAPass = true;
    bool laneRPass = true;
    bool laneBPass = true;
    std::ostringstream report;
    report << "AGENT-TOOL-SCHEMA-002 DIRECT\n";

    for (const auto& c : cases) {
        if (c.forceStrict) {
            _putenv_s("RAWRXD_TOOL_ARGS_STRICT", "1");
        } else {
            _putenv_s("RAWRXD_TOOL_ARGS_STRICT", "0");
        }
        const auto calls = ToolCallParser::parse(c.raw);
        if (calls.empty()) {
            report << "FAIL lane=" << c.lane << " parse_empty raw=" << c.raw << "\n";
            if (c.lane[0] == 'A') laneAPass = false;
            else if (c.lane[0] == 'R') laneRPass = false;
            else laneBPass = false;
            continue;
        }
        const ToolCall& call = calls.front();
        const ToolResult result = tools.dispatch(call);
        const bool accepted = (result.error != "schema_validation");
        const bool dispatched = result.dispatched;
        const bool ok =
            (accepted == c.expectAccept) &&
            (dispatched == c.expectDispatch) &&
            (c.expectDispatch ? true : !result.dispatched) &&
            (c.expectAccept ? (result.error != "schema_validation") : (result.error == "schema_validation"));

        report << (ok ? "PASS" : "FAIL")
               << " lane=" << c.lane
               << " tool=" << call.name
               << " expect_accept=" << (c.expectAccept ? 1 : 0)
               << " got_accept=" << (accepted ? 1 : 0)
               << " expect_dispatch=" << (c.expectDispatch ? 1 : 0)
               << " got_dispatch=" << (dispatched ? 1 : 0)
               << " error=" << (result.error.empty() ? "-" : result.error)
               << "\n";
        report << "  result_json=" << result.toJson() << "\n";
        if (!ok) {
            if (c.lane[0] == 'A') laneAPass = false;
            else if (c.lane[0] == 'R') laneRPass = false;
            else laneBPass = false;
        }
        // Lane A hard invariant
        if (c.lane[0] == 'A' && result.dispatched) laneAPass = false;
        if (c.lane[0] == 'A' && result.error != "schema_validation") laneAPass = false;
    }
    _putenv_s("RAWRXD_TOOL_ARGS_STRICT", "0");

    // Step-2 render dump (needs GGUF metadata for template contract; no Deep2 load).
    if (!cli.model.empty()) {
        try {
            const auto meta = GgufMetadataReader::read(cli.model);
            ChatTemplate tmpl(meta);
            std::vector<ChatMessage> msgs;
            msgs.push_back({Role::System, "You are the agent.", {}, {}});
            msgs.push_back({Role::User, "Fix main.c", {}, {}});
            msgs.push_back({Role::Assistant,
                            "TOOL_CALL: read_file {\"path\":\"main.c\"}", {}, {}});
            msgs.push_back({Role::Tool,
                            "{\"ok\":true,\"tool\":\"read_file\",\"dispatched\":true,\"output\":\"int x = DOES_NOT_EXIST;\"}",
                            "read_file", "call_1"});
            const auto rendered = tmpl.render(msgs, tools.definitions(), true);
            const fs::path dumpPath = outDir / "RAWRXD_AGENT_STEP2_RENDERED_PROMPT.txt";
            writeWholeFile(dumpPath, rendered);
            report << "STEP2_RENDER_DUMP=" << dumpPath.string() << "\n";
            const bool teachesEcho = rendered.find("TOOL_RESULT:") != std::string::npos;
            report << "STEP2_CONTAINS_TOOL_RESULT_LABEL=" << (teachesEcho ? 1 : 0) << "\n";
            report << "STEP2_CONTAINS_OBSERVATION=" << (rendered.find("Observation from") != std::string::npos ? 1 : 0) << "\n";
            report << "STEP2_ENDS_WITH_ASSISTANT_PROMPT="
                   << (rendered.size() >= 14 &&
                               rendered.rfind("<|assistant|>") != std::string::npos
                           ? 1
                           : 0)
                   << "\n";
        } catch (const std::exception& ex) {
            report << "STEP2_RENDER_DUMP_FAIL=" << ex.what() << "\n";
        }
    } else {
        report << "STEP2_RENDER_DUMP=skipped (pass --model for GGUF metadata)\n";
    }

    report << "LANE_A_MALFORMED_REJECT=" << (laneAPass ? "PASS" : "FAIL") << "\n";
    report << "LANE_B_VALID_ACCEPT=" << (laneBPass ? "PASS" : "FAIL") << "\n";
    report << "VALID_SCHEMA_LANE=" << (laneBPass ? "PASS" : "FAIL") << "\n";
    report << "AGENT-TOOL-SCHEMA-002="
           << ((laneAPass && laneBPass) ? "PASS" : "NOT_CERTIFIED") << "\n";

    const std::string text = report.str();
    std::cout << text;
    writeWholeFile(outDir / "AGENT_TOOL_SCHEMA_002_DIRECT.txt", text);

    // Lock stub
    std::ostringstream lock;
    lock << "{\n"
         << "  \"gate\": \"AGENT-TOOL-SCHEMA-002\",\n"
         << "  \"status\": \"" << ((laneAPass && laneBPass) ? "PASS" : "NOT_CERTIFIED") << "\",\n"
         << "  \"LANE_A_MALFORMED_REJECT\": \"" << (laneAPass ? "PASS" : "FAIL") << "\",\n"
         << "  \"LANE_B_VALID_ACCEPT\": \"" << (laneBPass ? "PASS" : "FAIL") << "\",\n"
         << "  \"VALID_SCHEMA_LANE\": \"" << (laneBPass ? "PASS" : "FAIL") << "\",\n"
         << "  \"note\": \"Architectural gate independent of TinyLlama. Full agent next-action is a separate defect.\"\n"
         << "}\n";
    writeWholeFile(outDir / "AGENT-TOOL-SCHEMA-002.lock.json", lock.str());

    return (laneAPass && laneBPass) ? EXIT_SUCCESS : EXIT_FAILURE;
}

static void printRuntimeInfo(const NativeInferenceClient& inference, const WorkspaceSandbox& sandbox) {
    const auto& metadata = inference.metadata();
    std::cout << "RawrXD Sovereign Agentic Runtime\n"
              << "architecture: " << (metadata.architecture.empty() ? "<unknown>" : metadata.architecture) << "\n"
              << "model: " << (metadata.modelName.empty() ? "<unnamed>" : metadata.modelName) << "\n"
              << "chat-template: " << templateFamilyName(inference.templateFamily()) << "\n"
              << "deep2-streaming: " << (inference.trueStreaming() ? "incremental" : "whole-response") << "\n"
              << "workspace: " << sandbox.root().string() << "\n"
              << "external inference runtime: none\n"
              << "cloud API: none\n\n";
}

} // namespace rawrxd::agentic

int main(int argc, char** argv) {
    using namespace rawrxd::agentic;
    try {
        const CliOptions cli = parseCli(argc, argv);
        if (cli.toolSchemaCert) {
            return runToolSchemaCert(cli);
        }
        WorkspaceSandbox sandbox(cli.workspace);

        const auto catalogModel =
            rawrxd::models::ModelCatalog::resolve(cli.model.string());

        if (!catalogModel) {
            throw std::runtime_error(
                "ModelCatalog could not resolve model spec: " +
                cli.model.string() +
                ". Set RAWRXD_MODEL_ROOT or use an absolute GGUF/blob path.");
        }

        if (catalogModel->storageKind ==
            rawrxd::models::StorageKind::GgufShards) {
            throw std::runtime_error(
                "RawrXD-Agentic unified metadata reader currently requires a "
                "GGUF/blob file. ModelCatalog resolved a shard directory: " +
                catalogModel->path.string() +
                ". Pass an individual GGUF shard/file until the directory "
                "metadata bridge is promoted to the unified runtime.");
        }

        if (catalogModel->blobOffset != 0) {
            throw std::runtime_error(
                "ModelCatalog found a wrapped GGUF payload at non-zero offset " +
                std::to_string(catalogModel->blobOffset) +
                ". Deep2 can consume wrapped Ollama blobs, but this unified "
                "agent runtime's GGUF metadata reader currently requires "
                "offset-0 GGUF. Use the Deep2 gateway path or an offset-0 model layer.");
        }

        std::cout
            << "catalog-model: "
            << catalogModel->displayName
            << "\n"
            << "catalog-path: "
            << catalogModel->path.string()
            << "\n"
            << "catalog-kind: "
            << rawrxd::models::storageKindName(catalogModel->storageKind)
            << "\n";

        NativeInferenceClient inference(catalogModel->path);
        ToolRegistry tools(sandbox);
        printRuntimeInfo(inference, sandbox);
        AgentConfig config;
        config.maxSteps = cli.maxSteps;
        config.maxTokensPerTurn = cli.maxTokens;
        config.streamToConsole = !cli.noStream;
        SovereignAgent agent(inference, tools, config);
        if (!cli.task.empty()) {
            const AgentResult result = agent.execute(cli.task);
            if (!result.success) {
                std::cerr << "[AGENT_FAIL] " << result.error << "\n";
                return EXIT_FAILURE;
            }
            if (cli.noStream) std::cout << result.answer << "\n";
            std::cout << "\n[AGENT_DONE]\nstatus=success\nsteps=" << result.steps << "\n";
            return EXIT_SUCCESS;
        }
        std::cout << "Interactive mode. Enter an empty line to quit.\n\n";
        for (;;) {
            std::cout << "rawrxd> " << std::flush;
            std::string task;
            if (!std::getline(std::cin, task)) break;
            task = trim(std::move(task));
            if (task.empty()) break;
            const AgentResult result = agent.execute(task);
            if (!result.success) std::cerr << "[AGENT_FAIL] " << result.error << "\n";
            else if (cli.noStream) std::cout << result.answer << "\n";
            std::cout << "\n";
        }
        return EXIT_SUCCESS;
    }
    catch (const std::exception& ex) {
        std::cerr << "[RAWRXD_AGENTIC_FATAL] " << ex.what() << "\n";
        return EXIT_FAILURE;
    }
}
