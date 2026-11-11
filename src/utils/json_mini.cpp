#include "json_mini.h"
#include <cstring>

namespace RawrXD {
namespace Json {

namespace {

// Skip whitespace
size_t skipWs(const std::string& s, size_t pos) {
    while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t' ||
                               s[pos] == '\n' || s[pos] == '\r')) {
        ++pos;
    }
    return pos;
}

// Parse a JSON string value, returning the decoded string and the position after closing quote
std::string parseString(const std::string& s, size_t& pos) {
    // s[pos] must be '"'
    ++pos; // skip opening quote
    std::string result;
    while (pos < s.size()) {
        char c = s[pos++];
        if (c == '"') {
            return result;
        }
        if (c == '\\') {
            if (pos >= s.size()) throw std::runtime_error("Unterminated escape in JSON string");
            char e = s[pos++];
            switch (e) {
                case '"': result.push_back('"'); break;
                case '\\': result.push_back('\\'); break;
                case '/': result.push_back('/'); break;
                case 'b': result.push_back('\b'); break;
                case 'f': result.push_back('\f'); break;
                case 'n': result.push_back('\n'); break;
                case 'r': result.push_back('\r'); break;
                case 't': result.push_back('\t'); break;
                case 'u': {
                    // 4 hex digits
                    if (pos + 4 > s.size()) throw std::runtime_error("Invalid unicode escape");
                    unsigned int cp = 0;
                    for (int i = 0; i < 4; ++i) {
                        char h = s[pos++];
                        cp <<= 4;
                        if (h >= '0' && h <= '9') cp |= (h - '0');
                        else if (h >= 'a' && h <= 'f') cp |= (h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') cp |= (h - 'A' + 10);
                        else throw std::runtime_error("Invalid hex digit in unicode escape");
                    }
                    // UTF-8 encode (BMP only for simplicity)
                    if (cp < 0x80) {
                        result.push_back(static_cast<char>(cp));
                    } else if (cp < 0x800) {
                        result.push_back(static_cast<char>(0xC0 | (cp >> 6)));
                        result.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                    } else {
                        result.push_back(static_cast<char>(0xE0 | (cp >> 12)));
                        result.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
                        result.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
                    }
                    break;
                }
                default:
                    throw std::runtime_error("Invalid escape sequence in JSON string");
            }
        } else {
            result.push_back(c);
        }
    }
    throw std::runtime_error("Unterminated JSON string");
}

Value parseValue(const std::string& s, size_t& pos);

Value parseObject(const std::string& s, size_t& pos) {
    Object obj;
    ++pos; // skip '{'
    pos = skipWs(s, pos);
    if (pos < s.size() && s[pos] == '}') {
        ++pos;
        return Value(obj);
    }
    while (pos < s.size()) {
        pos = skipWs(s, pos);
        if (pos >= s.size() || s[pos] != '"') throw std::runtime_error("Expected string key in JSON object");
        std::string key = parseString(s, pos);
        pos = skipWs(s, pos);
        if (pos >= s.size() || s[pos] != ':') throw std::runtime_error("Expected ':' in JSON object");
        ++pos; // skip ':'
        Value v = parseValue(s, pos);
        obj[key] = v;
        pos = skipWs(s, pos);
        if (pos < s.size() && s[pos] == ',') {
            ++pos;
            continue;
        }
        if (pos < s.size() && s[pos] == '}') {
            ++pos;
            return Value(obj);
        }
        throw std::runtime_error("Expected ',' or '}' in JSON object");
    }
    throw std::runtime_error("Unterminated JSON object");
}

Value parseArray(const std::string& s, size_t& pos) {
    Array arr;
    ++pos; // skip '['
    pos = skipWs(s, pos);
    if (pos < s.size() && s[pos] == ']') {
        ++pos;
        return Value(arr);
    }
    while (pos < s.size()) {
        Value v = parseValue(s, pos);
        arr.push_back(v);
        pos = skipWs(s, pos);
        if (pos < s.size() && s[pos] == ',') {
            ++pos;
            continue;
        }
        if (pos < s.size() && s[pos] == ']') {
            ++pos;
            return Value(arr);
        }
        throw std::runtime_error("Expected ',' or ']' in JSON array");
    }
    throw std::runtime_error("Unterminated JSON array");
}

Value parseNumber(const std::string& s, size_t& pos) {
    size_t start = pos;
    if (pos < s.size() && (s[pos] == '-' || s[pos] == '+')) ++pos;
    while (pos < s.size() && std::isdigit(static_cast<unsigned char>(s[pos]))) ++pos;
    bool hasFrac = false;
    if (pos < s.size() && s[pos] == '.') {
        hasFrac = true;
        ++pos;
        while (pos < s.size() && std::isdigit(static_cast<unsigned char>(s[pos]))) ++pos;
    }
    bool hasExp = false;
    if (pos < s.size() && (s[pos] == 'e' || s[pos] == 'E')) {
        hasExp = true;
        ++pos;
        if (pos < s.size() && (s[pos] == '+' || s[pos] == '-')) ++pos;
        while (pos < s.size() && std::isdigit(static_cast<unsigned char>(s[pos]))) ++pos;
    }
    std::string numStr = s.substr(start, pos - start);
    double d = std::stod(numStr);
    return Value(d);
}

Value parseValue(const std::string& s, size_t& pos) {
    pos = skipWs(s, pos);
    if (pos >= s.size()) throw std::runtime_error("Unexpected end of JSON input");
    char c = s[pos];
    if (c == '{') return parseObject(s, pos);
    if (c == '[') return parseArray(s, pos);
    if (c == '"') {
        std::string str = parseString(s, pos);
        return Value(str);
    }
    if (c == 't') {
        if (s.compare(pos, 4, "true") == 0) { pos += 4; return Value(true); }
        throw std::runtime_error("Invalid JSON literal");
    }
    if (c == 'f') {
        if (s.compare(pos, 5, "false") == 0) { pos += 5; return Value(false); }
        throw std::runtime_error("Invalid JSON literal");
    }
    if (c == 'n') {
        if (s.compare(pos, 4, "null") == 0) { pos += 4; return Value(); }
        throw std::runtime_error("Invalid JSON literal");
    }
    if (c == '-' || c == '+' || std::isdigit(static_cast<unsigned char>(c))) {
        return parseNumber(s, pos);
    }
    throw std::runtime_error("Unexpected character in JSON: " + std::string(1, c));
}

} // namespace

Value parse(const std::string& text) {
    size_t pos = 0;
    Value v = parseValue(text, pos);
    pos = skipWs(text, pos);
    if (pos < text.size()) throw std::runtime_error("Trailing characters after JSON value");
    return v;
}

void Value::dump(std::ostringstream& os, int indent, int level) const {
    std::string pad(indent * level, ' ');
    std::string padChild(indent * (level + 1), ' ');
    switch (m_type) {
        case Type::Null: os << "null"; break;
        case Type::Bool: os << (m_bool ? "true" : "false"); break;
        case Type::Number:
            if (std::floor(m_number) == m_number && !std::isinf(m_number)) {
                os << static_cast<long long>(m_number);
            } else {
                os << m_number;
            }
            break;
        case Type::String: {
            os << '"';
            for (char c : m_string) {
                switch (c) {
                    case '"': os << "\\\""; break;
                    case '\\': os << "\\\\"; break;
                    case '\b': os << "\\b"; break;
                    case '\f': os << "\\f"; break;
                    case '\n': os << "\\n"; break;
                    case '\r': os << "\\r"; break;
                    case '\t': os << "\\t"; break;
                    default:
                        if (static_cast<unsigned char>(c) < 0x20) {
                            char buf[8];
                            std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned char>(c));
                            os << buf;
                        } else {
                            os << c;
                        }
                }
            }
            os << '"';
            break;
        }
        case Type::Array: {
            os << "[";
            if (!m_array.empty()) {
                os << "\n";
                for (size_t i = 0; i < m_array.size(); ++i) {
                    os << padChild;
                    m_array[i].dump(os, indent, level + 1);
                    if (i + 1 < m_array.size()) os << ",";
                    os << "\n";
                }
                os << pad;
            }
            os << "]";
            break;
        }
        case Type::Object: {
            os << "{";
            if (!m_object.empty()) {
                os << "\n";
                size_t i = 0;
                for (const auto& kv : m_object) {
                    os << padChild << "\"" << kv.first << "\": ";
                    kv.second.dump(os, indent, level + 1);
                    if (i + 1 < m_object.size()) os << ",";
                    os << "\n";
                    ++i;
                }
                os << pad;
            }
            os << "}";
            break;
        }
    }
}

std::string Value::dump(int indent) const {
    std::ostringstream os;
    dump(os, indent, 0);
    return os.str();
}

} // namespace Json
} // namespace RawrXD
