#pragma once
#include <cstdlib>
#include <cstring>
#include <string>
namespace rawr::product {

inline std::string JsonString(const std::string& body, const char* key) {
    std::string pat = std::string("\"") + key + "\":";
    auto p = body.find(pat);
    if (p == std::string::npos) return {};
    p += pat.size();
    while (p < body.size() && (body[p] == ' ' || body[p] == '\t')) ++p;
    if (p >= body.size() || body[p] != '"') return {};
    ++p;
    std::string out;
    for (; p < body.size() && body[p] != '"'; ++p) {
        if (body[p] == '\\' && p + 1 < body.size()) {
            out.push_back(body[++p]);
            continue;
        }
        out.push_back(body[p]);
    }
    return out;
}

inline int JsonInt(const std::string& body, const char* key, int defv) {
    std::string pat = std::string("\"") + key + "\":";
    auto p = body.find(pat);
    if (p == std::string::npos) return defv;
    return atoi(body.c_str() + p + pat.size());
}

inline void JsonEscape(const std::string& in, std::string& out) {
    out.clear();
    out.reserve(in.size());
    for (char c : in) {
        if (c == '"' || c == '\\') out.push_back('\\');
        if (c == '\n') {
            out += "\\n";
            continue;
        }
        out.push_back(c);
    }
}

} // namespace rawr::product
