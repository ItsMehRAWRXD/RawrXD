#pragma once
#include <cctype>
#include <cstring>
#include <string>
namespace rawr::product {

enum class Perm : uint8_t { None = 0, Read = 1, Write = 2, Exec = 4, Git = 8 };

struct PermSet {
    uint32_t bits = (uint32_t)Perm::Read;
    bool has(Perm p) const { return (bits & (uint32_t)p) != 0; }
    void allow(Perm p) { bits |= (uint32_t)p; }
    void deny(Perm p) { bits &= ~(uint32_t)p; }
};

inline bool PathUnder(const std::string& root, const std::string& path) {
    if (root.empty() || path.empty() || path.size() < root.size()) return false;
    for (size_t i = 0; i < root.size(); ++i) {
        char a = root[i], b = path[i];
        if (a == '/') a = '\\';
        if (b == '/') b = '\\';
        if (tolower((unsigned char)a) != tolower((unsigned char)b)) return false;
    }
    return true;
}

inline bool CmdBlocked(const std::string& cmd) {
    const char* bad[] = {"curl ", "wget ", "Invoke-WebRequest", "git push",
                         "rm -rf", "format ", "del /s", nullptr};
    for (int i = 0; bad[i]; ++i)
        if (cmd.find(bad[i]) != std::string::npos) return true;
    return false;
}

} // namespace rawr::product
