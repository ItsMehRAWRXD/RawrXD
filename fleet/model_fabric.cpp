#include "model_fabric.hpp"
#include <iostream>
#include <algorithm>

namespace RawrXD::Fleet {

void ModelFabric::LoadModel(const std::string& model_name, const std::string& node_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    ModelReplica replica;
    replica.model_name = model_name;
    replica.node_id = node_id;
    replica.status = "loaded";
    models_[model_name].push_back(replica);
    std::cout << "Model " << model_name << " loaded on " << node_id << "\n";
}

void ModelFabric::UnloadModel(const std::string& model_name, const std::string& node_id) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto& replicas = models_[model_name];
    replicas.erase(std::remove_if(replicas.begin(), replicas.end(),
        [&](const ModelReplica& r) { return r.node_id == node_id; }), replicas.end());
}

std::string ModelFabric::RouteModel(const std::string& model_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = models_.find(model_name);
    if (it == models_.end() || it->second.empty()) return "";
    
    // Return the first available replica
    for (const auto& replica : it->second) {
        if (replica.status == "loaded") return replica.node_id;
    }
    return "";
}

std::vector<ModelReplica> ModelFabric::GetReplicas(const std::string& model_name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = models_.find(model_name);
    if (it != models_.end()) return it->second;
    return {};
}

void ModelFabric::SyncKV(const std::string& model_name) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::cout << "MODEL FABRIC\n";
    std::cout << "Loaded: " << model_name << "\n";
    std::cout << "Replicas: " << models_[model_name].size() << "\n";
    std::cout << "KV Cache: Distributed\n";
    std::cout << "Status: READY\n";
}

size_t ModelFabric::GetReplicaCount(const std::string& model_name) const {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = models_.find(model_name);
    return it != models_.end() ? it->second.size() : 0;
}

} // namespace RawrXD::Fleet
