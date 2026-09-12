// rawr_model_registry_cache.cpp — load/save registry cache
#include "rawr_model_registry.hpp"
#include <cstdlib>
#include <fstream>
#include <sstream>

namespace rawr {

static std::string CachePath() {
    if (const char* t = std::getenv("TEMP"))
        return std::string(t) + "\\rawrxd_model_registry.cache";
    return "G:\\~dev\\rawrxd\\.rawr_model_registry.cache";
}

bool ModelRegistry::loadCache() {
    std::ifstream in(CachePath());
    if (!in) return false;
    std::string line;
    if (!std::getline(in, line) || line.find("v1") == std::string::npos)
        return false;
    entries_.clear();
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        ModelEntry e;
        std::istringstream ss(line);
        std::string sz, mt, sh, val;
        if (!std::getline(ss, e.name, '|')) continue;
        std::getline(ss, e.tag, '|');
        std::getline(ss, e.id, '|');
        std::getline(ss, e.path, '|');
        std::getline(ss, sz, '|');
        std::getline(ss, mt, '|');
        std::getline(ss, e.architecture, '|');
        std::getline(ss, e.quantization, '|');
        std::getline(ss, sh, '|');
        std::getline(ss, val, '|');
        e.sizeBytes = (uint64_t)std::strtoull(sz.c_str(), nullptr, 10);
        e.modifiedTime = (uint64_t)std::strtoull(mt.c_str(), nullptr, 10);
        e.shardCount = (uint32_t)std::atoi(sh.c_str());
        e.valid = val == "1";
        entries_.push_back(std::move(e));
    }
    return !entries_.empty();
}

void ModelRegistry::saveCache() const {
    std::ofstream out(CachePath(), std::ios::trunc);
    if (!out) return;
    out << "# rawr_model_cache v1\n";
    for (const auto& e : entries_) {
        out << e.name << '|' << e.tag << '|' << e.id << '|' << e.path << '|'
            << e.sizeBytes << '|' << e.modifiedTime << '|' << e.architecture
            << '|' << e.quantization << '|' << e.shardCount << '|'
            << (e.valid ? 1 : 0) << '\n';
    }
}

} // namespace rawr
