// ============================================================================
// RawrXD JsonLite - Minimal JSON parser for Codex module
// Zero external dependencies - single header implementation
// ============================================================================

#pragma once
#include <string>
#include <vector>
#include <map>
#include <stdexcept>

namespace RawrXD {
namespace Codex {

// Minimal JSON value type
class JsonValue {
public:
    enum Type {
        Null,
        Bool,
        Number,
        String,
        Array,
        Object
    };

    JsonValue() : m_type(Null) {}
    JsonValue(bool val) : m_type(Bool), m_bool(val) {}
    JsonValue(double val) : m_type(Number), m_number(val) {}
    JsonValue(const std::string& val) : m_type(String), m_string(val) {}
    JsonValue(const char* val) : m_type(String), m_string(val) {}
    
    // Copy constructor
    JsonValue(const JsonValue& other) 
        : m_type(other.m_type)
        , m_bool(other.m_bool)
        , m_number(other.m_number)
        , m_string(other.m_string)
        , m_array(other.m_array)
        , m_object(other.m_object) {}
    
    // Static factory methods
    static JsonValue MakeArray() {
        JsonValue val;
        val.m_type = Array;
        return val;
    }
    
    static JsonValue MakeObject() {
        JsonValue val;
        val.m_type = Object;
        return val;
    }
    
    // Assignment operators
    JsonValue& operator=(const JsonValue& other) {
        if (this != &other) {
            m_type = other.m_type;
            m_bool = other.m_bool;
            m_number = other.m_number;
            m_string = other.m_string;
            m_array = other.m_array;
            m_object = other.m_object;
        }
        return *this;
    }
    JsonValue& operator=(bool val) {
        m_type = Bool;
        m_bool = val;
        return *this;
    }
    JsonValue& operator=(double val) {
        m_type = Number;
        m_number = val;
        return *this;
    }
    JsonValue& operator=(const std::string& val) {
        m_type = String;
        m_string = val;
        return *this;
    }
    JsonValue& operator=(const char* val) {
        m_type = String;
        m_string = val;
        return *this;
    }

    Type GetType() const { return m_type; }
    
    bool IsNull() const { return m_type == Null; }
    bool IsBool() const { return m_type == Bool; }
    bool IsNumber() const { return m_type == Number; }
    bool IsString() const { return m_type == String; }
    bool IsArray() const { return m_type == Array; }
    bool IsObject() const { return m_type == Object; }

    bool AsBool() const { return m_bool; }
    double AsNumber() const { return m_number; }
    const std::string& AsString() const { return m_string; }
    
    const std::vector<JsonValue>& AsArray() const { return m_array; }
    std::vector<JsonValue>& AsArray() { return m_array; }
    
    const std::map<std::string, JsonValue>& AsObject() const { return m_object; }
    std::map<std::string, JsonValue>& AsObject() { return m_object; }

    // Object accessors
    bool HasKey(const std::string& key) const {
        return m_object.find(key) != m_object.end();
    }
    
    const JsonValue& operator[](const std::string& key) const {
        auto it = m_object.find(key);
        if (it != m_object.end()) return it->second;
        static JsonValue null;
        return null;
    }
    
    JsonValue& operator[](const std::string& key) {
        m_type = Object;  // Ensure type is set to Object
        return m_object[key];
    }

    // Array accessors - const version
    const JsonValue& operator[](size_t index) const {
        if (index < m_array.size()) return m_array[index];
        static JsonValue null;
        return null;
    }
    
    // Array accessors - non-const version
    JsonValue& operator[](size_t index) {
        if (index >= m_array.size()) {
            m_array.resize(index + 1);
        }
        return m_array[index];
    }
    
    // Explicit array push
    void Push(const JsonValue& val) {
        m_array.push_back(val);
    }
    
    size_t Size() const {
        if (m_type == Array) return m_array.size();
        if (m_type == Object) return m_object.size();
        return 0;
    }

    // Serialization
    std::string Dump() const {
        switch (m_type) {
            case Null: return "null";
            case Bool: return m_bool ? "true" : "false";
            case Number: return std::to_string(m_number);
            case String: return "\"" + EscapeString(m_string) + "\"";
            case Array: {
                std::string result = "[";
                for (size_t i = 0; i < m_array.size(); ++i) {
                    if (i > 0) result += ",";
                    result += m_array[i].Dump();
                }
                return result + "]";
            }
            case Object: {
                std::string result = "{";
                bool first = true;
                for (const auto& [key, val] : m_object) {
                    if (!first) result += ",";
                    first = false;
                    result += "\"" + EscapeString(key) + "\":" + val.Dump();
                }
                return result + "}";
            }
        }
        return "";
    }

    // Parsing
    static JsonValue Parse(const std::string& json);

private:
    Type m_type;
    bool m_bool = false;
    double m_number = 0;
    std::string m_string;
    std::vector<JsonValue> m_array;
    std::map<std::string, JsonValue> m_object;

    static std::string EscapeString(const std::string& s) {
        std::string result;
        for (char c : s) {
            switch (c) {
                case '"': result += "\\\""; break;
                case '\\': result += "\\\\"; break;
                case '\b': result += "\\b"; break;
                case '\f': result += "\\f"; break;
                case '\n': result += "\\n"; break;
                case '\r': result += "\\r"; break;
                case '\t': result += "\\t"; break;
                default: result += c; break;
            }
        }
        return result;
    }

    static JsonValue ParseValue(const char*& p);
    static JsonValue ParseString(const char*& p);
    static JsonValue ParseNumber(const char*& p);
    static JsonValue ParseArray(const char*& p);
    static JsonValue ParseObject(const char*& p);
    static void SkipWhitespace(const char*& p);
};

// Inline implementation
inline JsonValue JsonValue::Parse(const std::string& json) {
    const char* p = json.c_str();
    return ParseValue(p);
}

inline void JsonValue::SkipWhitespace(const char*& p) {
    while (*p && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) ++p;
}

inline JsonValue JsonValue::ParseValue(const char*& p) {
    SkipWhitespace(p);
    
    if (*p == '{') return ParseObject(p);
    if (*p == '[') return ParseArray(p);
    if (*p == '"') return ParseString(p);
    if (*p == 't' || *p == 'f') {
        bool val = (p[0] == 't' && p[1] == 'r' && p[2] == 'u' && p[3] == 'e');
        p += val ? 4 : 5;
        return JsonValue(val);
    }
    if (*p == 'n') {
        p += 4; // null
        return JsonValue();
    }
    return ParseNumber(p);
}

inline JsonValue JsonValue::ParseString(const char*& p) {
    ++p; // Skip opening quote
    std::string result;
    while (*p && *p != '"') {
        if (*p == '\\' && p[1]) {
            ++p;
            switch (*p) {
                case '"': result += '"'; break;
                case '\\': result += '\\'; break;
                case '/': result += '/'; break;
                case 'b': result += '\b'; break;
                case 'f': result += '\f'; break;
                case 'n': result += '\n'; break;
                case 'r': result += '\r'; break;
                case 't': result += '\t'; break;
                default: result += *p; break;
            }
        } else {
            result += *p;
        }
        ++p;
    }
    if (*p == '"') ++p; // Skip closing quote
    return JsonValue(result);
}

inline JsonValue JsonValue::ParseNumber(const char*& p) {
    const char* start = p;
    if (*p == '-') ++p;
    while (*p >= '0' && *p <= '9') ++p;
    if (*p == '.') {
        ++p;
        while (*p >= '0' && *p <= '9') ++p;
    }
    if (*p == 'e' || *p == 'E') {
        ++p;
        if (*p == '+' || *p == '-') ++p;
        while (*p >= '0' && *p <= '9') ++p;
    }
    return JsonValue(std::stod(std::string(start, p - start)));
}

inline JsonValue JsonValue::ParseArray(const char*& p) {
    ++p; // Skip '['
    JsonValue arr;
    arr.m_type = Array;
    SkipWhitespace(p);
    if (*p == ']') { ++p; return arr; }
    
    while (*p) {
        arr.m_array.push_back(ParseValue(p));
        SkipWhitespace(p);
        if (*p == ',') { ++p; continue; }
        if (*p == ']') { ++p; break; }
    }
    return arr;
}

inline JsonValue JsonValue::ParseObject(const char*& p) {
    ++p; // Skip '{'
    JsonValue obj;
    obj.m_type = Object;
    SkipWhitespace(p);
    if (*p == '}') { ++p; return obj; }
    
    while (*p) {
        SkipWhitespace(p);
        std::string key = ParseString(p).AsString();
        SkipWhitespace(p);
        if (*p == ':') ++p;
        obj.m_object[key] = ParseValue(p);
        SkipWhitespace(p);
        if (*p == ',') { ++p; continue; }
        if (*p == '}') { ++p; break; }
    }
    return obj;
}

} // namespace Codex
} // namespace RawrXD
