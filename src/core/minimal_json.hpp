// ============================================================================
// Minimal JSON Parser - Zero Dependencies
// ============================================================================
// Lightweight JSON parser for model loading configuration
// No external dependencies - pure C++17
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <map>
#include <variant>
#include <cstdint>
#include <charconv>
#include <system_error>

namespace RawrXD {
namespace Core {

// Forward declarations
class JsonValue;

// JSON types using variant
using JsonNull = std::monostate;
using JsonBool = bool;
using JsonInt = int64_t;
using JsonFloat = double;
using JsonString = std::string;
using JsonArray = std::vector<JsonValue>;
using JsonObject = std::map<std::string, JsonValue>;

// ============================================================================
// JSON Value Container
// ============================================================================

class JsonValue {
public:
    using ValueType = std::variant<JsonNull, JsonBool, JsonInt, JsonFloat, JsonString, JsonArray, JsonObject>;

    JsonValue() = default;
    JsonValue(std::nullptr_t) : value_(JsonNull{}) {}
    JsonValue(bool b) : value_(b) {}
    JsonValue(int i) : value_(static_cast<JsonInt>(i)) {}
    JsonValue(int64_t i) : value_(i) {}
    JsonValue(double d) : value_(d) {}
    JsonValue(const char* s) : value_(std::string(s)) {}
    JsonValue(std::string s) : value_(std::move(s)) {}
    JsonValue(JsonArray arr) : value_(std::move(arr)) {}
    JsonValue(JsonObject obj) : value_(std::move(obj)) {}

    // Type checks
    bool IsNull() const { return std::holds_alternative<JsonNull>(value_); }
    bool IsBool() const { return std::holds_alternative<JsonBool>(value_); }
    bool IsInt() const { return std::holds_alternative<JsonInt>(value_); }
    bool IsFloat() const { return std::holds_alternative<JsonFloat>(value_); }
    bool IsString() const { return std::holds_alternative<JsonString>(value_); }
    bool IsArray() const { return std::holds_alternative<JsonArray>(value_); }
    bool IsObject() const { return std::holds_alternative<JsonObject>(value_); }

    // Getters with defaults
    bool GetBool(bool default_val = false) const {
        if (auto* p = std::get_if<JsonBool>(&value_)) return *p;
        return default_val;
    }

    int64_t GetInt(int64_t default_val = 0) const {
        if (auto* p = std::get_if<JsonInt>(&value_)) return *p;
        if (auto* p = std::get_if<JsonFloat>(&value_)) return static_cast<int64_t>(*p);
        return default_val;
    }

    double GetFloat(double default_val = 0.0) const {
        if (auto* p = std::get_if<JsonFloat>(&value_)) return *p;
        if (auto* p = std::get_if<JsonInt>(&value_)) return static_cast<double>(*p);
        return default_val;
    }

    const std::string& GetString(const std::string& default_val = "") const {
        if (auto* p = std::get_if<JsonString>(&value_)) return *p;
        return default_val;
    }

    const JsonArray& GetArray() const {
        static const JsonArray empty;
        if (auto* p = std::get_if<JsonArray>(&value_)) return *p;
        return empty;
    }

    const JsonObject& GetObject() const {
        static const JsonObject empty;
        if (auto* p = std::get_if<JsonObject>(&value_)) return *p;
        return empty;
    }

    // Object accessors
    bool HasKey(const std::string& key) const {
        if (auto* p = std::get_if<JsonObject>(&value_)) {
            return p->find(key) != p->end();
        }
        return false;
    }

    const JsonValue& operator[](const std::string& key) const {
        static const JsonValue null_val;
        if (auto* p = std::get_if<JsonObject>(&value_)) {
            auto it = p->find(key);
            if (it != p->end()) return it->second;
        }
        return null_val;
    }

    JsonValue& operator[](const std::string& key) {
        if (!IsObject()) {
            value_ = JsonObject{};
        }
        return std::get<JsonObject>(value_)[key];
    }

    // Array accessors
    size_t Size() const {
        if (auto* p = std::get_if<JsonArray>(&value_)) return p->size();
        if (auto* p = std::get_if<JsonObject>(&value_)) return p->size();
        return 0;
    }

    const JsonValue& operator[](size_t index) const {
        static const JsonValue null_val;
        if (auto* p = std::get_if<JsonArray>(&value_)) {
            if (index < p->size()) return (*p)[index];
        }
        return null_val;
    }

    // Iteration
    JsonObject::const_iterator begin() const {
        if (auto* p = std::get_if<JsonObject>(&value_)) return p->begin();
        static const JsonObject empty;
        return empty.begin();
    }

    JsonObject::const_iterator end() const {
        if (auto* p = std::get_if<JsonObject>(&value_)) return p->end();
        static const JsonObject empty;
        return empty.end();
    }

    // Serialization
    std::string ToString() const;
    std::string ToPrettyString(int indent = 0) const;

    // Parsing
    static JsonValue Parse(const std::string& json);
    static JsonValue Parse(const char* json, size_t len);

private:
    ValueType value_;

    // Parser state
    struct Parser {
        const char* data;
        size_t len;
        size_t pos;

        Parser(const char* d, size_t l) : data(d), len(l), pos(0) {}

        JsonValue ParseValue();
        JsonObject ParseObject();
        JsonArray ParseArray();
        std::string ParseString();
        JsonValue ParseNumber();
        void SkipWhitespace();
        bool Match(const char* s);
        char Peek() const { return pos < len ? data[pos] : '\0'; }
        char Get() { return pos < len ? data[pos++] : '\0'; }
    };

    // Serializer
    void Serialize(std::string& out, int indent, int current_indent) const;
};

// ============================================================================
// Convenience Functions
// ============================================================================

inline JsonValue MakeJsonObject() { return JsonValue(JsonObject{}); }
inline JsonValue MakeJsonArray() { return JsonValue(JsonArray{}); }

// Parse from file
JsonValue JsonParseFile(const std::string& filepath);

// Parse with error info
struct JsonParseResult {
    JsonValue value;
    bool success = false;
    std::string error;
    size_t error_pos = 0;
};

JsonParseResult JsonParseEx(const std::string& json);

} // namespace Core
} // namespace RawrXD
