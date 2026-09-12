// rawr_model_registry_resolve.cpp — name → ModelEntry
#include "rawr_model_registry.hpp"
#include "rawr_model_registry_util.hpp"
#include "../deep2/RawrModelAlias.hpp"

namespace rawr {

bool ModelRegistry::resolve(const std::string& name, ModelEntry& out) const {
    if (name.empty()) return false;
    if (Deep2::GgufPath::IsLoadableModelFile(name)) {
        out = {};
        out.name = name;
        out.path = name;
        out.tag = "latest";
        out.shardCount = 1;
        out.valid = true;
        regutil::FileStat(name.c_str(), out.sizeBytes, out.modifiedTime);
        out.id = regutil::CheapId(name.c_str(), out.sizeBytes, out.modifiedTime);
        return true;
    }
    for (const auto& e : entries_) {
        if (_stricmp(e.name.c_str(), name.c_str()) == 0) {
            out = e;
            return e.valid && !e.path.empty();
        }
    }
    std::string want = Deep2::rawr_run::StripOllamaTag(name.c_str());
    for (const auto& e : entries_) {
        if (_stricmp(e.name.c_str(), want.c_str()) == 0) {
            out = e;
            return e.valid && !e.path.empty();
        }
    }
    Deep2::rawr_run::AliasResolve hit{};
    if (Deep2::rawr_run::ResolveModelAlias(name.c_str(), hit) && hit.resolved) {
        out = {};
        out.name = name;
        out.path = hit.path;
        out.tag = "latest";
        out.shardCount = hit.shards ? hit.shards : 1;
        out.valid = true;
        regutil::FileStat(out.path.c_str(), out.sizeBytes, out.modifiedTime);
        out.id = regutil::CheapId(out.path.c_str(), out.sizeBytes,
                                  out.modifiedTime);
        return true;
    }
    int best = 0;
    const ModelEntry* bp = nullptr;
    for (const auto& e : entries_) {
        Deep2::rawr_run::LocalModelUnit u;
        u.alias = e.name;
        u.path = e.path;
        u.shards = e.shardCount;
        u.isDir = e.shardCount > 1;
        int s = Deep2::rawr_run::MatchScore(name, u);
        if (s > best) {
            best = s;
            bp = &e;
        }
    }
    if (bp && best >= 300) {
        out = *bp;
        return out.valid;
    }
    return false;
}

} // namespace rawr
