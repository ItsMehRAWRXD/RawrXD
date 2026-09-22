#pragma once
#include "InferenceAdapter.hpp"

namespace rawrxd::swarm48 {

class SharedModelRegistry {
public:
    explicit SharedModelRegistry(IInferenceAdapter& backend) : backend_(backend) {}

    std::shared_ptr<const ResidentModel> acquire(const ModelLoadRequest& req);
    std::size_t resident_count() const;
    bool contains(const ModelLoadRequest& req) const;
    std::uint64_t resident_bytes(DeviceId device) const;
    void collect_unused();

private:
    struct Entry { std::shared_ptr<ResidentModel> model; };
    static std::string key_for(const ModelLoadRequest& req);

    IInferenceAdapter& backend_;
    mutable std::mutex mu_;
    std::unordered_map<std::string, Entry> entries_;
};

} // namespace rawrxd::swarm48
