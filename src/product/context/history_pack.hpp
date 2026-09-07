#pragma once
#include <string>
#include <vector>
namespace rawr::product {

struct Turn {
    std::string role;
    std::string text;
};

inline std::vector<Turn> PackHistory(const std::vector<Turn>& in, size_t keep,
                                     size_t maxChars) {
    std::vector<Turn> out;
    size_t start = in.size() > keep ? in.size() - keep : 0;
    size_t used = 0;
    for (size_t i = start; i < in.size(); ++i) {
        size_t n = in[i].role.size() + in[i].text.size() + 2;
        if (used + n > maxChars && !out.empty()) break;
        out.push_back(in[i]);
        used += n;
    }
    return out;
}

} // namespace rawr::product
