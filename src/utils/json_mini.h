#pragma once

// Minimal JSON parser/writer — zero external dependencies.
// Supports: objects, arrays, strings, numbers, booleans, null.
// Intended for LSP JSON-RPC messages and settings serialization.
#pragma once

#include <string>
#include <vector>
#include <map>
#include <variant>
#include <optional>
#include <stdexcept>
#include <cctype>
#include <sstream>
#include <cmath>

namespace RawrXD {
namespace Json {

class Value;

using Object = std::map<std::string, Value>;
using Array = std::vector<Value>;

class Value {
public:
    enum class Type { Null, Bool, Number, String, Array, Object };

    Value() : m_type(Type::Null) {}
    Value(bool v) : m_type(Type::Bool), m_bool(v) {}
    Value(double v) : m_type(Type::Number), m_number(v) {}
    Value(int v) : m_type(Type::Number), m_number(static_cast<double>(v)) {}
    Value(const std::string& v) : m_type(Type::String), m_string(v) {}
    Value(const char* v) : m_type(Type::String), m_string(v) {}
    Value(const Object& v) : m_type(Type::Object), m_object(v) {}
    Value(const Array& v) : m_type(Type::Array), m_array(v) {}

    Type type() const { return m_type; }
    bool isNull() const { return m_type == Type::Null; }
    bool isBool() const { return m_type == Type::Bool; }
    bool isNumber() const { return m_type == Type::Number; }
    bool isString() const { return m_type == Type::String; }
    bool isArray() const { return m_type == Type::Array; }
    bool isObject() const { return m_type == Type::Object; }

    bool asBool() const { return m_bool; }
    double asNumber() const { return m_number; }
    const std::string& asString() const { return m_string; }
    const Object& asObject() const { return m_object; }
    const Array& asArray() const { return m_array; }

    bool has(const std::string& key) const {
        return m_type == Type::Object && m_object.find(key) != m_object.end();
    }

    const Value& at(const std::string& key) const {
        if (m_type != Type::Object) throw std::runtime_error("Value is not an object");
        auto it = m_object.find(key);
        if (it == m_object.end()) throw std::runtime_error("Key not found: " + key);
        return it->second;
    }

    const Value& at(size_t index) const {
        if (m_type != Type::Array) throw std::runtime_error("Value is not an array");
        if (index >= m_array.size()) throw std::runtime_error("Array index out of range");
        return m_array[index];
    }

    Value& at(const std::string& key) {
        return const_cast<Value&>(static_cast<const Value&>(*this).at(key));
    }

    Value& at(size_t index) {
        return const_cast<Value&>(static_cast<const Value&>(*this).at(index));
    }

    Value& operator[](const std::string& key) {
        if (m_type != Type::Object) m_type = Type::Object;
        return m_object[key];
    }

    Value& operator[](size_t index) {
        if (m_type != Type::Array) m_type = Type::Array;
        if (index >= m_array.size()) m_array.resize(index + 1);
        return m_array[index];
    }

    std::string dump(int indent = 2) const;

private:
    Type m_type;
    bool m_bool = false;
    double m_number = 0.0;
    std::string m_string;
    Object m_object;
    Array m_array;

    void dump(std::ostringstream& os, int indent, int level) const;
};

// Parse a JSON string into a Value.
Value parse(const std::string& text);

// Serialize a Value to JSON string.
inline std::string dump(const Value& v, int indent = 2) { return v.dump(indent); }

} // namespace Json
} // namespace RawrXD
