// rawr_diagnostic_scrubber.hpp — keep stdout answer-only
#pragma once
#include <string>

namespace rawr::style {

inline bool LooksLikeDiagnostic(const std::string& line) {
    return line.find("[Deep2Engine]") != std::string::npos ||
           line.find("[ResidencyManager]") != std::string::npos ||
           line.find("[ThreadPool]") != std::string::npos ||
           line.find("[StreamEngine]") != std::string::npos ||
           line.find("HOTPATH_") != std::string::npos ||
           line.find("MODEL=") == 0 ||
           line.find("OLLAMA_USED=") == 0 ||
           line.find("SEMANTIC_SAFE=") != std::string::npos;
}

inline std::string ScrubDiagnostics(const std::string& text) {
    std::string out;
    size_t i = 0;
    while (i < text.size()) {
        size_t e = text.find('\n', i);
        if (e == std::string::npos) e = text.size();
        std::string line = text.substr(i, e - i);
        if (!LooksLikeDiagnostic(line)) {
            if (!out.empty()) out.push_back('\n');
            out += line;
        }
        i = e + (e < text.size() ? 1 : 0);
        if (e >= text.size()) break;
    }
    return out;
}

} // namespace rawr::style
