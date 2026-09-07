#pragma once
#include "../repo/cpp_scan.hpp"
#include <cstring>
#include <string>
#include <vector>
namespace rawr::product {

inline int EvidenceExists(const std::vector<Sym>& syms, const std::string& name) {
    if (name.empty()) return 0;
    for (const auto& s : syms)
        if (s.name == name) return 1;
    return 0;
}

inline int GuardClaim(const std::vector<Sym>& syms, const std::string& claim) {
    // Refuse "file/symbol exists" unless the index has it.
    const char* keys[] = {"class ", "function ", "file ", nullptr};
    std::string name = claim;
    for (int i = 0; keys[i]; ++i) {
        auto p = claim.find(keys[i]);
        if (p == std::string::npos) continue;
        name = claim.substr(p + std::strlen(keys[i]));
        while (!name.empty() && (name.back() == '.' || name.back() == ' '))
            name.pop_back();
        break;
    }
    auto sp = name.find(' ');
    if (sp != std::string::npos) name.resize(sp);
    return EvidenceExists(syms, name);
}

} // namespace rawr::product
