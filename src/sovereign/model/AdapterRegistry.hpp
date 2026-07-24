// ============================================================================
// AdapterRegistry.hpp - Adapter Registry for Model Adapters
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

namespace Sovereign {

enum class AdapterType { LORA, QLORA, LORA_HAI, ADALORA, DORA, IA3, LORA_GA, OFT, BOFT };

struct AdapterInfo {
    std::string name;
    AdapterType type;
    std::string path;
    std::string baseModel;
    std::string version;
    float scale;
    bool isActive;
    uint64_t loadedAt;
    uint64_t weightCount;
    uint64_t totalParams;
};

class AdapterRegistry {
public:
    AdapterRegistry();
    ~AdapterRegistry();

    bool Register(const std::string& name, AdapterType type, const std::string& path);
    bool Unregister(const std::string& name);
    bool Load(const std::string& name);
    bool Unload(const std::string& name);
    bool Activate(const std::string& name);
    bool Deactivate(const std::string& name);

    AdapterInfo GetInfo(const std::string& name) const;
    std::vector<AdapterInfo> List() const;
    std::vector<AdapterInfo> GetActive() const;
    bool IsLoaded(const std::string& name) const;
    bool IsActive(const std::string& name) const;
    size_t GetCount() const { return adapters_.size(); }

    bool Merge(const std::vector<std::string>& adapterNames, const std::string& outputPath);
    bool Export(const std::string& name, const std::string& outputPath);

    struct RegistryStats {
        uint64_t totalRegistrations;
        uint64_t activeAdapters;
        uint64_t loadedAdapters;
        uint64_t mergesPerformed;
    };
    RegistryStats GetStats() const { return stats_; }

private:
    std::unordered_map<std::string, AdapterInfo> adapters_;
    RegistryStats stats_;
    mutable std::mutex mutex_;
};

} // namespace Sovereign
