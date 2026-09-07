#pragma once
#include <cctype>
#include <fstream>
#include <string>
#include <vector>
namespace rawr::product {

struct Sym {
    std::string name;
    std::string kind; // include|class|fn|macro
    std::string file;
    int line = 0;
};

inline bool identStart(char c) {
    return std::isalpha((unsigned char)c) || c == '_';
}
inline bool identChar(char c) {
    return std::isalnum((unsigned char)c) || c == '_';
}

inline std::string takeIdent(const std::string& s, size_t i) {
    if (i >= s.size() || !identStart(s[i])) return {};
    size_t j = i + 1;
    while (j < s.size() && identChar(s[j])) j++;
    return s.substr(i, j - i);
}

inline void ScanCppLine(const std::string& file, int line, const std::string& s,
                        std::vector<Sym>& out) {
    auto t = s;
    while (!t.empty() && (t[0] == ' ' || t[0] == '\t')) t.erase(0, 1);
    if (t.rfind("#include", 0) == 0) {
        auto q = t.find_first_of("\"<");
        auto e = t.find_last_of("\">");
        if (q != std::string::npos && e > q)
            out.push_back(Sym{t.substr(q + 1, e - q - 1), "include", file, line});
        return;
    }
    if (t.rfind("class ", 0) == 0 || t.rfind("struct ", 0) == 0) {
        size_t sp = t.find(' ');
        auto n = takeIdent(t, sp + 1);
        if (!n.empty()) out.push_back(Sym{n, "class", file, line});
        return;
    }
    size_t par = t.find('(');
    if (par != std::string::npos && par > 0) {
        size_t i = par;
        while (i > 0 && (t[i - 1] == ' ' || t[i - 1] == '\t')) i--;
        size_t e = i;
        while (i > 0 && identChar(t[i - 1])) i--;
        auto n = t.substr(i, e - i);
        if (!n.empty() && n != "if" && n != "for" && n != "while" && n != "switch")
            out.push_back(Sym{n, "fn", file, line});
    }
}

inline bool ScanCppFile(const std::string& path, std::vector<Sym>& out) {
    std::ifstream in(path);
    if (!in) return false;
    std::string line;
    int n = 0;
    while (std::getline(in, line) && n < 4000) {
        n++;
        ScanCppLine(path, n, line, out);
    }
    return true;
}

} // namespace rawr::product
