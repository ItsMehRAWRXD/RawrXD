#pragma once
#include <cctype>
#include <cstdlib>
#include <string>
#include <vector>
namespace rawr::product {

struct Frame {
    std::string fn;
    std::string file;
    int line = 0;
};

inline Frame ParseFrame(const std::string& s) {
    Frame f;
    auto bang = s.find('!');
    auto at = s.find(" at ");
    if (bang != std::string::npos) {
        size_t start = bang + 1;
        size_t end = at == std::string::npos ? s.size() : at;
        while (end > start && s[end - 1] == ' ') end--;
        f.fn = s.substr(start, end - start);
        auto par = f.fn.find('(');
        if (par != std::string::npos) f.fn.resize(par);
    }
    if (at != std::string::npos) {
        std::string rest = s.substr(at + 4);
        auto col = rest.find(':');
        if (col != std::string::npos) {
            f.file = rest.substr(0, col);
            f.line = atoi(rest.c_str() + col + 1);
        } else {
            f.file = rest;
        }
    }
    return f;
}

inline std::vector<Frame> ParseStack(const std::string& dump) {
    std::vector<Frame> out;
    size_t i = 0;
    while (i < dump.size()) {
        size_t n = dump.find('\n', i);
        if (n == std::string::npos) n = dump.size();
        Frame f = ParseFrame(dump.substr(i, n - i));
        if (!f.fn.empty()) out.push_back(f);
        i = n + 1;
    }
    return out;
}

} // namespace rawr::product
