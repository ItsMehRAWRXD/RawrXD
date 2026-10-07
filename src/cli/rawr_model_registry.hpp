// rawr_model_registry.hpp — shared list/run model registry
#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace rawr {

struct ModelEntry {
    std::string name;
    std::string tag;
    std::string id;
    std::string path;
    uint64_t sizeBytes = 0;
    uint64_t modifiedTime = 0;
    std::string architecture;
    std::string quantization;
    uint32_t shardCount = 1;
    bool valid = false;
};

struct ModelRegistry {
    static ModelRegistry& instance();
    void scan(bool refresh);
    const std::vector<ModelEntry>& entries() const { return entries_; }
    const std::vector<std::string>& roots() const { return roots_; }
    bool resolve(const std::string& name, ModelEntry& out) const;
    bool resolvePath(const std::string& name, std::string& pathOut) const;
    bool inspect(const std::string& name, ModelEntry& out) const;

private:
    std::vector<ModelEntry> entries_;
    std::vector<std::string> roots_;
    bool scanned_ = false;
    void collectRoots();
    void scanRoots();
    bool loadCache();
    void saveCache() const;
};

bool ResolveModel(const std::string& alias, std::string& pathOut);

} // namespace rawr
