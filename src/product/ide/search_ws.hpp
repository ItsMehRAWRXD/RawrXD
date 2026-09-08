#pragma once
#include "../repo/repo_scanner.hpp"
#include <string>
namespace rawr::product {

inline bool SearchWorkspace(const std::string& root, const char* needle,
                            std::string& hit) {
    hit.clear();
    if (root.empty() || !needle || !needle[0]) return false;
    RepoIndex idx;
    if (!ScanRepo(root, idx, 64)) return false;
    for (const auto& s : idx.symbols) {
        if (s.name.find(needle) != std::string::npos) {
            hit = s.name;
            return true;
        }
    }
    for (const auto& f : idx.files) {
        if (f.find(needle) != std::string::npos) {
            hit = f;
            return true;
        }
    }
    return false;
}

} // namespace rawr::product
