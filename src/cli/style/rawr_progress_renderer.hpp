// rawr_progress_renderer.hpp — plan/progress lines to stderr
#pragma once
#include <cstdio>
#include <string>
#include <vector>

namespace rawr::style {

struct ProgressStep {
    std::string label;
    bool done = false;
};

inline std::string RenderProgress(const std::vector<ProgressStep>& steps,
                                  int current) {
    std::string out;
    out += "PLAN\n";
    for (size_t i = 0; i < steps.size(); ++i) {
        const char* mark = steps[i].done ? "[x]" : ((int)i == current ? "[>]" : "[ ]");
        out += "  ";
        out += mark;
        out += " ";
        out += steps[i].label;
        out += "\n";
    }
    return out;
}

inline void PrintProgress(const std::vector<ProgressStep>& steps, int current) {
    fputs(RenderProgress(steps, current).c_str(), stderr);
    fflush(stderr);
}

} // namespace rawr::style
