#pragma once
#include "../deep2/RawrModelAlias.hpp"
#include <string>
namespace rawr {
inline bool ResolveModel(const std::string& alias, std::string& pathOut) {
    Deep2::rawr_run::AliasResolve hit{};
    if (!Deep2::rawr_run::ResolveModelAlias(alias.c_str(), hit)) return false;
    pathOut = hit.path;
    return hit.resolved && !pathOut.empty();
}
} // namespace rawr
