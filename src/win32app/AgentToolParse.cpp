#include "AgentProduct.hpp"
#include <cctype>

namespace {
void SkipWs(const std::string& s, size_t& i) {
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i]))) ++i;
}
bool GrabString(const std::string& s, size_t& i, std::string& out) {
    SkipWs(s, i);
    if (i >= s.size() || s[i] != '"') return false;
    ++i;
    out.clear();
    while (i < s.size()) {
        char c = s[i++];
        if (c == '\\' && i < s.size()) { out.push_back(s[i++]); continue; }
        if (c == '"') return true;
        out.push_back(c);
    }
    return false;
}
size_t Match(const std::string& s, size_t i, char open, char close) {
    if (i >= s.size() || s[i] != open) return std::string::npos;
    int depth = 0;
    for (size_t j = i; j < s.size(); ++j) {
        if (s[j] == '"') {
            ++j;
            while (j < s.size() && s[j] != '"') { if (s[j] == '\\') ++j; ++j; }
            if (j >= s.size()) return std::string::npos;
            continue;
        }
        if (s[j] == open) ++depth;
        else if (s[j] == close && --depth == 0) return j;
    }
    return std::string::npos;
}
bool Field(const std::string& obj, const char* key, std::string& value, bool raw) {
    const std::string pat = std::string("\"") + key + "\"";
    auto p = obj.find(pat);
    if (p == std::string::npos) return false;
    p = obj.find(':', p + pat.size());
    if (p == std::string::npos) return false;
    size_t i = p + 1;
    SkipWs(obj, i);
    if (i >= obj.size()) return false;
    if (obj[i] == '"') return GrabString(obj, i, value);
    if (!raw) return false;
    char end = obj[i] == '{' ? '}' : ']';
    size_t j = Match(obj, i, obj[i], end);
    if (j == std::string::npos) return false;
    value = obj.substr(i, j - i + 1);
    return true;
}
}

bool AgentParseToolCalls(const std::string& text, std::vector<AgentToolCall>& out) {
    out.clear();
    auto key = text.find("\"tool_calls\"");
    if (key == std::string::npos) return false;
    auto lb = text.find('[', key);
    if (lb == std::string::npos) return false;
    auto rb = Match(text, lb, '[', ']');
    if (rb == std::string::npos) return false;
    size_t i = lb + 1;
    while (i < rb && out.size() < 8) {
        auto ob = text.find('{', i);
        if (ob == std::string::npos || ob > rb) break;
        auto oe = Match(text, ob, '{', '}');
        if (oe == std::string::npos || oe > rb) return false;
        AgentToolCall call;
        std::string obj = text.substr(ob, oe - ob + 1);
        if (!Field(obj, "name", call.name, false)) return false;
        Field(obj, "arguments", call.arguments, true);
        for (char& c : call.name)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        out.push_back(call);
        i = oe + 1;
    }
    return !out.empty();
}
