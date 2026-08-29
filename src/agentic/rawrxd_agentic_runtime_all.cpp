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
};

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
            skipValue(r, type);
        }
        return m;
    }
private:
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
        << "Use tools when they are necessary to complete the task. "
        << "Do not invent tool results.\n\n"
        << "TOOLS:\n"
        << toolsAsOpenAIJson(tools)
        << "\n\n"
        << "When calling a tool, emit exactly one JSON object in this form:\n"
        << "{\"name\":\"tool_name\",\"arguments\":{...}}\n"
        << "After a tool result is provided, continue from that result. "
        << "When the task is complete, answer normally without a tool object.";
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
        : metadata_(std::move(metadata)), family_(detectFamily(metadata_)) {}

    TemplateFamily family() const { return family_; }
    const GgufMetadata& metadata() const { return metadata_; }

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
            name.find("llama-3") != std::string::npos || name.find("llama 3") != std::string::npos) return TemplateFamily::Llama3;
        if (arch.find("phi") != std::string::npos || templateLower.find("<|assistant|>") != std::string::npos) return TemplateFamily::Phi3;
        if (arch.find("gemma") != std::string::npos || templateLower.find("<start_of_turn>") != std::string::npos) return TemplateFamily::Gemma;
        if (arch.find("mistral") != std::string::npos || templateLower.find("[inst]") != std::string::npos) return TemplateFamily::Mistral;
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

    static std::string renderChatML(const std::vector<ChatMessage>& messages,
                                    const std::vector<ToolDefinition>& tools,
                                    bool addGenerationPrompt, bool hermes) {
        const auto expanded = withToolSystemMessage(messages, tools);
        std::ostringstream out;
        for (const auto& message : expanded) {
            out << "<|im_start|>" << roleName(message.role) << "\n";
            if (message.role == Role::Tool && hermes) {
                out << "<tool_response>\n" << message.content << "\n</tool_response>";
            } else {
                out << message.content;
            }
            out << "<|im_end|>\n";
        }
        if (addGenerationPrompt) out << "<|im_start|>assistant\n";
        return out.str();
    }

    static std::string renderQwen(const std::vector<ChatMessage>& messages,
                                   const std::vector<ToolDefinition>& tools,
                                   bool addGenerationPrompt) {
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
        std::ostringstream out;
        for (const auto& message : expanded) {
            out << "<|im_start|>" << roleName(message.role) << "\n";
            if (message.role == Role::Tool) {
                out << "<tool_response>\n" << message.content << "\n</tool_response>";
            } else {
                out << message.content;
            }
            out << "<|im_end|>\n";
        }
        if (addGenerationPrompt) out << "<|im_start|>assistant\n";
        return out.str();
    }

    static std::string renderLlama3(const std::vector<ChatMessage>& messages,
                                     const std::vector<ToolDefinition>& tools,
                                     bool addGenerationPrompt) {
        const auto expanded = withToolSystemMessage(messages, tools);
        std::ostringstream out;
        out << "<|begin_of_text|>";
        for (const auto& message : expanded) {
            out << "<|start_header_id|>" << roleName(message.role) << "<|end_header_id|>\n\n"
                << message.content << "<|eot_id|>";
        }
        if (addGenerationPrompt) out << "<|start_header_id|>assistant<|end_header_id|>\n\n";
        return out.str();
    }

    static std::string renderPhi3(const std::vector<ChatMessage>& messages,
                                   const std::vector<ToolDefinition>& tools,
                                   bool addGenerationPrompt) {
        const auto expanded = withToolSystemMessage(messages, tools);
        std::ostringstream out;
        for (const auto& message : expanded) {
            out << "<|" << roleName(message.role) << "|>\n" << message.content << "<|end|>\n";
        }
        if (addGenerationPrompt) out << "<|assistant|>\n";
        return out.str();
    }

    static std::string renderGemma(const std::vector<ChatMessage>& messages,
                                    const std::vector<ToolDefinition>& tools,
                                    bool addGenerationPrompt) {
        const auto expanded = withToolSystemMessage(messages, tools);
        std::ostringstream out;
        out << "<bos>";
        for (const auto& message : expanded) {
            const char* role = message.role == Role::Assistant ? "model" : "user";
            out << "<start_of_turn>" << role << "\n";
            if (message.role == Role::System) out << "[SYSTEM]\n";
            else if (message.role == Role::Tool) out << "[TOOL_RESULT]\n";
            out << message.content << "<end_of_turn>\n";
        }
        if (addGenerationPrompt) out << "<start_of_turn>model\n";
        return out.str();
    }

    static std::string renderMistral(const std::vector<ChatMessage>& messages,
                                      const std::vector<ToolDefinition>& tools,
                                      bool addGenerationPrompt) {
        const auto expanded = withToolSystemMessage(messages, tools);
        std::ostringstream out;
        std::string pendingSystem;
        for (const auto& message : expanded) {
            if (message.role == Role::System) { pendingSystem = message.content; continue; }
            if (message.role == Role::User) {
                out << "<s>[INST] ";
                if (!pendingSystem.empty()) { out << pendingSystem << "\n\n"; pendingSystem.clear(); }
                out << message.content << " [/INST]";
            } else if (message.role == Role::Assistant) {
                out << " " << message.content << "</s>";
            } else if (message.role == Role::Tool) {
                out << " [TOOL_RESULT] " << message.content << " [/TOOL_RESULT]";
            }
        }
        (void)addGenerationPrompt;
        return out.str();
    }

    static std::string renderGeneric(const std::vector<ChatMessage>& messages,
                                      const std::vector<ToolDefinition>& tools,
                                      bool addGenerationPrompt) {
        const auto expanded = withToolSystemMessage(messages, tools);
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

    std::string generate(const std::string& prompt, int maxTokens,
                         const std::function<bool(std::string_view)>& onChunk) {
        if (!engine_) throw std::runtime_error("Deep2 engine is unavailable");
        return generateImpl(*engine_, prompt, maxTokens, onChunk);
    }

private:
    std::unique_ptr<Deep2> engine_;

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

    std::string toJson() const {
        std::ostringstream out;
        out << "{" << "\"ok\":" << (success ? "true" : "false") << ","
            << "\"tool\":" << jsonQuote(tool) << ","
            << "\"exit_code\":" << exitCode << ","
            << "\"output\":" << jsonQuote(output) << "}";
        return out.str();
    }
};

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
        if (it == handlers_.end()) return ToolResult{false, call.name, "unknown tool: " + call.name, -1};
        try { return it->second(call.argumentsJson); }
        catch (const std::exception& ex) { return ToolResult{false, call.name, ex.what(), -1}; }
    }

private:
    using Handler = std::function<ToolResult(const std::string&)>;
    WorkspaceSandbox sandbox_;
    std::unordered_map<std::string, ToolDefinition> definitions_;
    std::unordered_map<std::string, Handler> handlers_;
    std::set<std::string> allowedExecutables_ {
        "cmake", "ninja", "ctest", "git", "powershell", "pwsh",
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
                 R"({"type":"object","properties":{"path":{"type":"string"},"search":{"type":"string"},"replace":{"type":"string"},"replace_all":{"type":"boolean"}},"required":["path","search","replace"]})"},
            [&](const std::string& args) {
                const auto path = sandbox_.resolveExisting(requiredString(args, "path"));
                const std::string search = requiredString(args, "search");
                const std::string replacement = requiredString(args, "replace");
                if (search.empty()) throw std::runtime_error("search text must not be empty");
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

    std::string ChatSync(const std::vector<ChatMessage>& messages,
                          const std::vector<ToolDefinition>& tools,
                          int maxTokens) {
        const std::string prompt = chatTemplate_.render(messages, tools, true);
        return deep2_.generate(prompt, maxTokens, {});
    }

    std::string ChatStream(const std::vector<ChatMessage>& messages,
                            const std::vector<ToolDefinition>& tools,
                            int maxTokens,
                            const StreamCallback& callback) {
        const std::string prompt = chatTemplate_.render(messages, tools, true);
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
            full = deep2_.generate(prompt, maxTokens, onChunk);
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
                out << "{" << "\"id\":" << jsonQuote(step.toolCalls[j].id) << ","
                    << "\"name\":" << jsonQuote(step.toolCalls[j].name) << ","
                    << "\"arguments\":" << step.toolCalls[j].argumentsJson << "}";
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
    bool streamToConsole = true;
    bool saveTranscript = true;
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
        std::vector<ChatMessage> messages;
        messages.push_back({Role::System, systemPrompt(), {}, {}});
        messages.push_back({Role::User, task, {}, {}});
        const auto toolDefinitions = tools_.definitions();
        std::set<std::string> previousCallFingerprints;
        AgentTranscript transcript;

        for (int step = 1; step <= config_.maxSteps; ++step) {
            TranscriptStep record;
            record.step = step;
            record.timestamp = isoTimeNow();
            std::string response;
            const auto inferStart = std::chrono::steady_clock::now();
            try {
                response = inference_.ChatStream(messages, toolDefinitions, config_.maxTokensPerTurn,
                    [&](const StreamEvent& event) {
                        if (event.kind == StreamEvent::Kind::Text && config_.streamToConsole) {
                            std::cout << event.text << std::flush;
                        }
                        return true;
                    });
            }
            catch (const std::exception& ex) {
                return AgentResult{false, false, step, {}, ex.what()};
            }
            const auto inferEnd = std::chrono::steady_clock::now();
            record.inferenceMs = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(inferEnd - inferStart).count());
            record.modelResponse = response;
            if (config_.streamToConsole) std::cout << "\n";

            const auto calls = ToolCallParser::parse(response);
            record.toolCalls = calls;
            if (calls.empty()) {
                transcript.add(std::move(record));
                persistTranscript(transcript);
                return AgentResult{true, false, step, response, {}};
            }

            messages.push_back({Role::Assistant, response, {}, {}});
            const auto toolStart = std::chrono::steady_clock::now();
            for (const auto& call : calls) {
                const std::string fingerprint = call.name + "\n" + call.argumentsJson;
                if (!previousCallFingerprints.insert(fingerprint).second) {
                    const ToolResult loopResult{false, call.name, "identical tool call repeated; change strategy before retrying", -2};
                    record.toolResults.push_back(loopResult);
                    messages.push_back({Role::Tool, loopResult.toJson(), call.name, call.id});
                    continue;
                }
                ToolResult result = tools_.dispatch(call);
                record.toolResults.push_back(result);
                messages.push_back({Role::Tool, result.toJson(), call.name, call.id});
            }
            const auto toolEnd = std::chrono::steady_clock::now();
            record.toolMs = static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(toolEnd - toolStart).count());
            transcript.add(std::move(record));
        }
        persistTranscript(transcript);
        return AgentResult{false, true, config_.maxSteps, {}, "agent reached configured step limit"};
    }

private:
    NativeInferenceClient& inference_;
    ToolRegistry& tools_;
    AgentConfig config_;

    static std::string systemPrompt() {
        return "You are RawrXD's local sovereign coding agent. "
               "You operate only on the provided workspace and local tools. "
               "Complete the user's task end-to-end. "
               "Inspect before editing. "
               "Use exact tool results; never claim a build or test passed unless "
               "you actually ran it and observed a successful result. "
               "When a command fails, inspect the failure, modify the source if "
               "appropriate, and retry with a changed strategy. "
               "Prefer narrow, correct edits over unrelated changes. "
               "Do not repeatedly issue an identical failed tool call. "
               "When finished, provide the concise final result and the validation "
               "you performed.";
    }

    void persistTranscript(const AgentTranscript& transcript) const {
        if (!config_.saveTranscript) return;
        try {
            const fs::path path = fs::current_path() / "RAWRXD_AGENT_TRANSCRIPT.json";
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
        else if (arg == "--help" || arg == "-h") {
            std::cout << "RawrXD-Agentic.exe --model path|friendly-name|model:tag|sha256-blob --workspace D:\\rawrxd [--task \"...\"] [--max-steps 16] [--max-tokens 2048] [--no-stream]\n";
            std::exit(EXIT_SUCCESS);
        }
        else throw std::runtime_error("unknown argument: " + arg);
    }
    if (options.model.empty()) throw std::runtime_error("--model is required");
    if (options.workspace.empty()) options.workspace = fs::current_path();
    return options;
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
