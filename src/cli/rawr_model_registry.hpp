#pragma once
#include "../deep2/RawrModelAlias.hpp"
#include "../deep2/RawrModelDiscover.hpp"
#include <string>
#include <vector>
namespace rawr {
inline bool ResolveModel(const std::string& alias, std::string& pathOut) {
    Deep2::rawr_run::AliasResolve hit{};
    if (!Deep2::rawr_run::ResolveModelAlias(alias.c_str(), hit)) return false;
    pathOut = hit.path;
    return hit.resolved && !pathOut.empty();
}

inline std::vector<Deep2::rawr_run::LocalModelUnit> ListLocalModels() {
    std::vector<Deep2::rawr_run::LocalModelUnit> out;
    Deep2::rawr_run::DiscoverLocalModels(out);
    return out;
}
} // namespace rawr
