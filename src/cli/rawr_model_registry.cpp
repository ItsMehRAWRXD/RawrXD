// rawr_model_registry.cpp — scan facade + path resolve
#include "rawr_model_registry.hpp"
#include "rawr_model_registry_util.hpp"
#include "../deep2/RawrModelAlias.hpp"

namespace rawr {

ModelRegistry& ModelRegistry::instance() {
    static ModelRegistry g;
    return g;
}

void ModelRegistry::scan(bool refresh) {
    collectRoots();
    if (!refresh && scanned_ && !entries_.empty()) return;
    if (!refresh && loadCache()) {
        scanned_ = true;
        return;
    }
    scanRoots();
    saveCache();
    scanned_ = true;
}

bool ModelRegistry::resolvePath(const std::string& name,
                                std::string& pathOut) const {
    ModelEntry e;
    if (!resolve(name, e)) return false;
    pathOut = e.path;
    return !pathOut.empty();
}

bool ModelRegistry::inspect(const std::string& name, ModelEntry& out) const {
    return resolve(name, out);
}

bool ResolveModel(const std::string& alias, std::string& pathOut) {
    auto& reg = ModelRegistry::instance();
    reg.scan(false);
    return reg.resolvePath(alias, pathOut);
}

} // namespace rawr
