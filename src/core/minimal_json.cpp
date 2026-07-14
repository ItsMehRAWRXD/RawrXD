// ============================================================================
// Minimal JSON Parser Implementation
// ============================================================================

#include "minimal_json.hpp"
#include <cctype>
#include <fstream>
#include <sstream>

namespace RawrXD {
namespace Core {

// ============================================================================
// Parser Implementation
// ============================================================================

void JsonValue::Parser::SkipWhitespace() {
    while (pos < len && std::isspace(static_cast<unsigned char>(data[pos]))) {
        ++pos;
    }
}

bool JsonValue::Parser::Match(const char* s) {
    size_t slen = std::strlen(s);
    if (pos + slen > len) return false;
    if (std::strncmp(data + pos, s, slen) != 0) return false;
    pos += slen;
    return true;
}

JsonValue JsonValue::Parser::ParseValue() {
    SkipWhitespace();
    if (pos >= len) return JsonValue();

    char c = Peek();
    
    if (c == '{') return ParseObject();
    if (c == '[') return ParseArray();
    if (c == '"') return ParseString();
    if (c == 't' || c == 'f') {
        if (Match("true")) return JsonValue(true);
        if (Match("false")) return JsonValue(false);
    }
    if (c == 'n' && Match("null")) return JsonValue(nullptr);
    
    // Number
    if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) {
        return ParseNumber();
    }
    
    return JsonValue();
}

JsonObject JsonValue::Parser::ParseObject() {
    JsonObject obj;
    Get(); // consume '{'
    
    SkipWhitespace();
    if (Peek() == '}') {
        Get();
        return obj;
    }
    
    while (true) {
        SkipWhitespace();
        std::string key = ParseString();
        
        SkipWhitespace();
        if (Get() != ':') break; // error
        
        SkipWhitespace();
        JsonValue val = ParseValue();
        obj[std::move(key)] = std::move(val);
        
        SkipWhitespace();
        char c = Get();
        if (c == '}') break;
        if (c != ',') break; // error
    }
    
    return obj;
}

JsonArray JsonValue::Parser::ParseArray() {
    JsonArray arr;
    Get(); // consume '['
    
    SkipWhitespace();
    if (Peek() == ']') {
        Get();
        return arr;
    }
    
    while (true) {
        SkipWhitespace();
        JsonValue val = ParseValue();
        arr.push_back(std::move(val));
        
        SkipWhitespace();
        char c = Get();
        if (c == ']') break;
        if (c != ',') break; // error
    }
    
    return arr;
}

std::string JsonValue::Parser::ParseString() {
    std::string result;
    Get(); // consume opening '"'
    
    while (pos < len) {
        char c = Get();
        if (c == '"') break;
        if (c == '\\' && pos < len) {
            char next = Get();
            switch (next) {
                case '"': result += '"'; break;
                case '\\': result += '\\'; break;
                case '/': result += '/'; break;
                case 'b': result += '\b'; break;
                case 'f': result += '\f'; break;
                case 'n': result += '\n'; break;
                case 'r': result += '\r'; break;
                case 't': result += '\t'; break;
                default: result += next; break;
            }
        } else {
            result += c;
        }
    }
    
    return result;
}

JsonValue JsonValue::Parser::ParseNumber() {
    size_t start = pos;
    bool is_float = false;
    
    if (Peek() == '-') Get();
    
    while (pos < len && std::isdigit(static_cast<unsigned char>(Peek()))) {
        Get();
    }
    
    if (Peek() == '.') {
        is_float = true;
        Get();
        while (pos < len && std::isdigit(static_cast<unsigned char>(Peek()))) {
            Get();
        }
    }
    
    if (Peek() == 'e' || Peek() == 'E') {
        is_float = true;
        Get();
        if (Peek() == '+' || Peek() == '-') Get();
        while (pos < len && std::isdigit(static_cast<unsigned char>(Peek()))) {
            Get();
        }
    }
    
    std::string num_str(data + start, pos - start);
    
    if (is_float) {
        try {
            double val = std::stod(num_str);
            return JsonValue(val);
        } catch (...) {
            return JsonValue(0.0);
        }
    } else {
        try {
            int64_t val = std::stoll(num_str);
            return JsonValue(val);
        } catch (...) {
            return JsonValue(0);
        }
    }
}

// ============================================================================
// Static Parse Methods
// ============================================================================

JsonValue JsonValue::Parse(const std::string& json) {
    return Parse(json.c_str(), json.length());
}

JsonValue JsonValue::Parse(const char* json, size_t len) {
    Parser parser(json, len);
    return parser.ParseValue();
}

JsonParseResult JsonParseEx(const std::string& json) {
    JsonParseResult result;
    try {
        result.value = JsonValue::Parse(json);
        result.success = true;
    } catch (...) {
        result.error = "Parse error";
        result.error_pos = 0;
    }
    return result;
}

JsonValue JsonParseFile(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file) return JsonValue();
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    return JsonValue::Parse(buffer.str());
}

// ============================================================================
// Serialization
// ============================================================================

std::string JsonValue::ToString() const {
    std::string result;
    Serialize(result, 0, 0);
    return result;
}

std::string JsonValue::ToPrettyString(int indent) const {
    std::string result;
    Serialize(result, indent, 0);
    return result;
}

void JsonValue::Serialize(std::string& out, int indent, int current_indent) const {
    auto add_indent = [&]() {
        if (indent > 0) {
            out += '\n';
            out.append(current_indent, ' ');
        }
    };
    
    std::visit([&](auto&& arg) {
        using T = std::decay_t<decltype(arg)>;
        
        if constexpr (std::is_same_v<T, JsonNull>) {
            out += "null";
        }
        else if constexpr (std::is_same_v<T, JsonBool>) {
            out += arg ? "true" : "false";
        }
        else if constexpr (std::is_same_v<T, JsonInt>) {
            out += std::to_string(arg);
        }
        else if constexpr (std::is_same_v<T, JsonFloat>) {
            char buf[64];
            std::snprintf(buf, sizeof(buf), "%.6g", arg);
            out += buf;
        }
        else if constexpr (std::is_same_v<T, JsonString>) {
            out += '"';
            for (char c : arg) {
                switch (c) {
                    case '"': out += "\\\""; break;
                    case '\\': out += "\\\\"; break;
                    case '\b': out += "\\b"; break;
                    case '\f': out += "\\f"; break;
                    case '\n': out += "\\n"; break;
                    case '\r': out += "\\r"; break;
                    case '\t': out += "\\t"; break;
                    default: out += c; break;
                }
            }
            out += '"';
        }
        else if constexpr (std::is_same_v<T, JsonArray>) {
            out += '[';
            for (size_t i = 0; i < arg.size(); ++i) {
                if (i > 0) out += ",";
                add_indent();
                arg[i].Serialize(out, indent, current_indent + indent);
            }
            out += ']';
        }
        else if constexpr (std::is_same_v<T, JsonObject>) {
            out += '{';
            bool first = true;
            for (const auto& [key, val] : arg) {
                if (!first) out += ",";
                first = false;
                add_indent();
                out += '"' + key + "\":";
                if (indent > 0) out += ' ';
                val.Serialize(out, indent, current_indent + indent);
            }
            out += '}';
        }
    }, value_);
}

} // namespace Core
} // namespace RawrXD
