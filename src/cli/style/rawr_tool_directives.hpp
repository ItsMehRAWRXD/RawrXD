// rawr_tool_directives.hpp — parse TOOL TERM_START / TOOL PATCH ...
#pragma once
#include <cctype>
#include <string>
#include <vector>

namespace rawr::style {

struct ToolDirective {
    std::string tool; // TERM_START, TERM_TAIL, TERM_STOP, PATCH, READ, BUILD
    std::string arg1;
    std::string arg2;
    bool ok = false;
};

inline ToolDirective ParseToolDirective(const std::string& line) {
    ToolDirective d{};
    std::string s = line;
    while (!s.empty() && isspace((unsigned char)s.front())) s.erase(s.begin());
    if (s.rfind("TOOL ", 0) != 0 && s.rfind("tool ", 0) != 0) return d;
    s = s.substr(5);
    while (!s.empty() && isspace((unsigned char)s.front())) s.erase(s.begin());
    auto sp = s.find(' ');
    if (sp == std::string::npos) {
        d.tool = s;
        d.ok = !d.tool.empty();
        return d;
    }
    d.tool = s.substr(0, sp);
    std::string rest = s.substr(sp + 1);
    auto sp2 = rest.find(' ');
    if (sp2 == std::string::npos) {
        d.arg1 = rest;
    } else {
        d.arg1 = rest.substr(0, sp2);
        d.arg2 = rest.substr(sp2 + 1);
    }
    d.ok = !d.tool.empty();
    return d;
}

inline std::vector<ToolDirective> ExtractToolDirectives(const std::string& text) {
    std::vector<ToolDirective> out;
    size_t i = 0;
    while (i < text.size()) {
        size_t e = text.find('\n', i);
        if (e == std::string::npos) e = text.size();
        auto d = ParseToolDirective(text.substr(i, e - i));
        if (d.ok) out.push_back(d);
        i = e + (e < text.size() ? 1 : 0);
        if (e >= text.size()) break;
    }
    return out;
}

} // namespace rawr::style
