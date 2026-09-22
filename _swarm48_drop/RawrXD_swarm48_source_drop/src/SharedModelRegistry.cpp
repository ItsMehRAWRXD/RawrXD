#include "rawrxd/swarm48/SharedModelRegistry.hpp"
#include <sstream>

namespace rawrxd::swarm48 {

std::string SharedModelRegistry::key_for(const ModelLoadRequest& req) {
    return std::to_string(req.device) + "|" + req.model_path;
}

std::shared_ptr<const ResidentModel> SharedModelRegistry::acquire(const ModelLoadRequest& req) {
    const auto key = key_for(req);
    std::lock_guard lock(mu_);
    if (auto it = entries_.find(key); it != entries_.end()) return it->second.model;

    auto loaded = std::make_shared<ResidentModel>(backend_.load_shared(req));
    if (!loaded->handle) throw std::runtime_error("backend returned null model handle");
    if (loaded->model_path.empty()) loaded->model_path = req.model_path;
    loaded->device = req.device;
    entries_.emplace(key, Entry{loaded});
    return loaded;
}

bool SharedModelRegistry::contains(const ModelLoadRequest& req) const {
    std::lock_guard lock(mu_);
    return entries_.contains(key_for(req));
}

std::size_t SharedModelRegistry::resident_count() const {
    std::lock_guard lock(mu_);
    return entries_.size();
}

std::uint64_t SharedModelRegistry::resident_bytes(DeviceId device) const {
    std::lock_guard lock(mu_);
    std::uint64_t total = 0;
    for (const auto& [_, e] : entries_) if (e.model->device == device) total += e.model->weight_bytes;
    return total;
}

void SharedModelRegistry::collect_unused() {
    std::lock_guard lock(mu_);
    for (auto it = entries_.begin(); it != entries_.end();) {
        // Registry owns one shared_ptr. If nobody else holds it, release backend residency.
        if (it->second.model.use_count() == 1) {
            backend_.unload_shared(it->second.model->handle);
            it = entries_.erase(it);
        } else ++it;
    }
}

} // namespace rawrxd::swarm48
