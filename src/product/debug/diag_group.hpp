#pragma once
#include <map>
#include <string>
#include <vector>
namespace rawr::product {

struct Diag {
    std::string file;
    int line = 0;
    std::string msg;
};

struct DiagGroup {
    std::string key;
    std::vector<Diag> items;
};

inline std::string DiagKey(const Diag& d) {
    auto c = d.msg.find(':');
    return (c == std::string::npos) ? d.msg : d.msg.substr(0, c);
}

inline std::vector<DiagGroup> GroupDiags(const std::vector<Diag>& in) {
    std::map<std::string, DiagGroup> m;
    for (const auto& d : in) {
        std::string k = DiagKey(d);
        m[k].key = k;
        m[k].items.push_back(d);
    }
    std::vector<DiagGroup> out;
    for (auto& kv : m) out.push_back(kv.second);
    return out;
}

} // namespace rawr::product
