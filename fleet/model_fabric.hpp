#pragma once
#include <string>
#include <vector>
#include <map>
#include <mutex>

namespace RawrXD::Fleet {

struct ModelReplica {
    std::string model_name;
    std::string node_id;
    std::string status;
    size_t kv_cache_size = 0;
};

class ModelFabric {
public:
    ModelFabric() = default;
    ~ModelFabric() = default;

    void LoadModel(const std::string& model_name, const std::string& node_id);
    void UnloadModel(const std::string& model_name, const std::string& node_id);
    std::string RouteModel(const std::string& model_name);
    std::vector<ModelReplica> GetReplicas(const std::string& model_name) const;
    void SyncKV(const std::string& model_name);
    size_t GetReplicaCount(const std::string& model_name) const;

private:
    std::map<std::string, std::vector<ModelReplica>> models_;
    mutable std::mutex mutex_;
};

} // namespace RawrXD::Fleet
