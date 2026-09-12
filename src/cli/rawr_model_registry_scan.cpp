// rawr_model_registry_scan.cpp — roots + recursive scan
#include "rawr_model_registry.hpp"
#include "rawr_model_registry_util.hpp"
#include <cstdlib>

namespace rawr {

void ModelRegistry::collectRoots() {
    roots_.clear();
    auto push = [&](const char* r) {
        if (!r || !r[0]) return;
#ifdef _WIN32
        DWORD a = GetFileAttributesA(r);
        if (a == INVALID_FILE_ATTRIBUTES || !(a & FILE_ATTRIBUTE_DIRECTORY))
            return;
#endif
        for (const auto& e : roots_)
            if (_stricmp(e.c_str(), r) == 0) return;
        roots_.emplace_back(r);
    };
    push("G:\\~dev\\rawrxd");
    push("G:\\~dev\\rawrxd\\models");
    push("G:\\~dev\\rawrxd\\rawrxd_test_models");
    push("G:\\OllamaModels");
    push("F:\\OllamaModels");
    if (const char* home = std::getenv("USERPROFILE")) {
        std::string p = std::string(home) + "\\.ollama\\models";
        push(p.c_str());
    }
    if (const char* e = std::getenv("RAWR_MODEL_PATH")) push(e);
    if (const char* e = std::getenv("RAWRXD_MODEL_ROOT")) push(e);
}

void ModelRegistry::scanRoots() {
    entries_.clear();
    std::vector<Deep2::rawr_run::LocalModelUnit> units;
    for (const auto& r : roots_)
        Deep2::rawr_run::ScanDirRecursive(r.c_str(), 0, units);
    for (const auto& u : units) {
        ModelEntry e;
        e.name = u.alias;
        e.tag = "latest";
        e.path = u.path;
        e.shardCount = u.shards ? u.shards : 1;
        e.quantization = regutil::GuessQuant(u.alias.c_str());
        if (u.isDir || e.shardCount > 1) {
            uint32_t n = 0;
            e.sizeBytes = regutil::DirShardBytes(u.path.c_str(), n);
            if (n) e.shardCount = n;
            e.valid = e.sizeBytes > 0;
        } else {
            e.valid = regutil::FileStat(u.path.c_str(), e.sizeBytes,
                                        e.modifiedTime);
            if (e.valid && !Deep2::GgufPath::IsLoadableModelFile(u.path))
                e.valid = false;
        }
        e.id = regutil::CheapId(e.path.c_str(), e.sizeBytes, e.modifiedTime);
        if (e.architecture.empty()) e.architecture = "-";
        if (e.quantization.empty()) e.quantization = "-";
        entries_.push_back(std::move(e));
    }
}

} // namespace rawr
