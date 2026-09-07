// rawr_diff_renderer.hpp — unified diff style renderer (no deps)
#pragma once
#include <sstream>
#include <string>
#include <vector>

namespace rawr::style {

inline std::vector<std::string> SplitLines(const std::string& t) {
    std::vector<std::string> lines;
    size_t i = 0;
    while (i < t.size()) {
        size_t e = t.find('\n', i);
        if (e == std::string::npos) e = t.size();
        std::string line = t.substr(i, e - i);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(line);
        i = e + (e < t.size() ? 1 : 0);
        if (e >= t.size()) break;
    }
    return lines;
}

inline std::string RenderUnifiedDiff(const std::string& path,
                                     const std::string& before,
                                     const std::string& after) {
    auto a = SplitLines(before);
    auto b = SplitLines(after);
    std::ostringstream os;
    os << "--- a/" << path << "\n+++ b/" << path << "\n";
    size_t n = a.size() > b.size() ? a.size() : b.size();
    os << "@@ -1," << a.size() << " +1," << b.size() << " @@\n";
    for (size_t i = 0; i < n; ++i) {
        const std::string* la = i < a.size() ? &a[i] : nullptr;
        const std::string* lb = i < b.size() ? &b[i] : nullptr;
        if (la && lb && *la == *lb) os << " " << *la << "\n";
        else {
            if (la) os << "-" << *la << "\n";
            if (lb) os << "+" << *lb << "\n";
        }
    }
    return os.str();
}

} // namespace rawr::style
