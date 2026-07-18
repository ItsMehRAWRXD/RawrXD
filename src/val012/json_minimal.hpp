// Minimal JSON implementation for VAL-012
// Single-header, no external dependencies
// Based on nlohmann/json API subset

#ifndef VAL012_JSON_MINIMAL_HPP
#define VAL012_JSON_MINIMAL_HPP

#include <string>
#include <vector>
#include <map>
#include <sstream>
#include <iomanip>
#include <stdexcept>

namespace val012 {

class json {
public:
    enum class value_t {
        null,
        object,
        array,
        string,
        boolean,
        number_integer,
        number_float
    };

    json() : m_type(value_t::null) {}
    json(std::nullptr_t) : m_type(value_t::null) {}
    json(bool b) : m_type(value_t::boolean), m_bool(b) {}
    json(int i) : m_type(value_t::number_integer), m_int(i) {}
    json(long i) : m_type(value_t::number_integer), m_int(i) {}
    json(long long i) : m_type(value_t::number_integer), m_int(i) {}
    json(double d) : m_type(value_t::number_float), m_float(d) {}
    json(const char* s) : m_type(value_t::string), m_string(s) {}
    json(const std::string& s) : m_type(value_t::string), m_string(s) {}
    json(std::initializer_list<json> init) : m_type(value_t::array) {
        m_array = std::vector<json>(init);
    }
    
    // Constructor from vector of strings (for arrays)
    json(const std::vector<std::string>& vec) : m_type(value_t::array) {
        for (const auto& s : vec) {
            m_array.push_back(json(s));
        }
    }

    // Type checking
    bool is_null() const { return m_type == value_t::null; }
    bool is_object() const { return m_type == value_t::object; }
    bool is_array() const { return m_type == value_t::array; }
    bool is_string() const { return m_type == value_t::string; }
    bool is_boolean() const { return m_type == value_t::boolean; }
    bool is_number() const { return m_type == value_t::number_integer || m_type == value_t::number_float; }
    bool is_number_integer() const { return m_type == value_t::number_integer; }
    bool is_number_float() const { return m_type == value_t::number_float; }

    // Accessors
    bool get_bool() const {
        if (m_type != value_t::boolean) throw std::runtime_error("Not a boolean");
        return m_bool;
    }

    long long get_int() const {
        if (m_type != value_t::number_integer) throw std::runtime_error("Not an integer");
        return m_int;
    }

    double get_float() const {
        if (m_type == value_t::number_integer) return static_cast<double>(m_int);
        if (m_type != value_t::number_float) throw std::runtime_error("Not a number");
        return m_float;
    }

    std::string get_string() const {
        if (m_type != value_t::string) throw std::runtime_error("Not a string");
        return m_string;
    }

    // Object operations
    json& operator[](const std::string& key) {
        if (m_type == value_t::null) m_type = value_t::object;
        if (m_type != value_t::object) throw std::runtime_error("Not an object");
        return m_object[key];
    }

    const json& operator[](const std::string& key) const {
        if (m_type != value_t::object) throw std::runtime_error("Not an object");
        auto it = m_object.find(key);
        if (it == m_object.end()) throw std::runtime_error("Key not found: " + key);
        return it->second;
    }

    bool contains(const std::string& key) const {
        if (m_type != value_t::object) return false;
        return m_object.find(key) != m_object.end();
    }

    // Array operations
    json& operator[](size_t index) {
        if (m_type == value_t::null) {
            m_type = value_t::array;
            m_array.resize(index + 1);
        }
        if (m_type != value_t::array) throw std::runtime_error("Not an array");
        if (index >= m_array.size()) m_array.resize(index + 1);
        return m_array[index];
    }

    const json& operator[](size_t index) const {
        if (m_type != value_t::array) throw std::runtime_error("Not an array");
        if (index >= m_array.size()) throw std::runtime_error("Index out of bounds");
        return m_array[index];
    }

    void push_back(const json& val) {
        if (m_type == value_t::null) m_type = value_t::array;
        if (m_type != value_t::array) throw std::runtime_error("Not an array");
        m_array.push_back(val);
    }

    size_t size() const {
        if (m_type == value_t::array) return m_array.size();
        if (m_type == value_t::object) return m_object.size();
        return 0;
    }

    // Iteration
    auto begin() { return m_array.begin(); }
    auto end() { return m_array.end(); }
    auto begin() const { return m_array.begin(); }
    auto end() const { return m_array.end(); }

    // Serialization
    std::string dump(int indent = -1) const {
        std::ostringstream oss;
        dump_impl(oss, indent, 0);
        return oss.str();
    }

    // Static constructors
    static json object() {
        json j;
        j.m_type = value_t::object;
        return j;
    }

    static json array() {
        json j;
        j.m_type = value_t::array;
        return j;
    }

    // Parse (minimal implementation)
    static json parse(const std::string& s) {
        // Minimal parser - just handle simple cases
        // For full JSON support, use a proper library
        json result;
        // TODO: Implement proper parser
        return result;
    }

private:
    value_t m_type;
    bool m_bool = false;
    long long m_int = 0;
    double m_float = 0.0;
    std::string m_string;
    std::vector<json> m_array;
    std::map<std::string, json> m_object;

    void dump_impl(std::ostringstream& oss, int indent, int level) const {
        std::string indent_str(indent > 0 ? indent * level : 0, ' ');
        std::string newline = indent >= 0 ? "\n" : "";
        std::string space = indent >= 0 ? " " : "";

        switch (m_type) {
            case value_t::null:
                oss << "null";
                break;
            case value_t::boolean:
                oss << (m_bool ? "true" : "false");
                break;
            case value_t::number_integer:
                oss << m_int;
                break;
            case value_t::number_float:
                oss << std::fixed << std::setprecision(6) << m_float;
                break;
            case value_t::string:
                oss << "\"" << escape_string(m_string) << "\"";
                break;
            case value_t::array:
                oss << "[" << newline;
                for (size_t i = 0; i < m_array.size(); ++i) {
                    if (i > 0) oss << "," << newline;
                    oss << std::string(indent > 0 ? indent * (level + 1) : 0, ' ');
                    m_array[i].dump_impl(oss, indent, level + 1);
                }
                oss << newline << indent_str << "]";
                break;
            case value_t::object:
                oss << "{" << newline;
                bool first = true;
                for (const auto& [key, val] : m_object) {
                    if (!first) oss << "," << newline;
                    first = false;
                    oss << std::string(indent > 0 ? indent * (level + 1) : 0, ' ');
                    oss << "\"" << escape_string(key) << "\":" << space;
                    val.dump_impl(oss, indent, level + 1);
                }
                oss << newline << indent_str << "}";
                break;
        }
    }

    std::string escape_string(const std::string& s) const {
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
};

} // namespace val012

#endif // VAL012_JSON_MINIMAL_HPP
