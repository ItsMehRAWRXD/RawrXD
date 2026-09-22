#pragma once
#include "Common.hpp"

namespace rawrxd::swarm48 {

struct KvPoolConfig {
    std::uint64_t total_bytes{};
    std::uint32_t page_bytes{256u * 1024u};
};

struct KvAllocation {
    KvHandle handle{};
    AgentId agent{};
    DeviceId device{};
    std::vector<std::uint32_t> pages;
};

class PagedKVPool {
public:
    PagedKVPool(DeviceId device, KvPoolConfig cfg);

    KvHandle create(AgentId agent);
    bool ensure_bytes(KvHandle handle, std::uint64_t bytes);
    void trim_to_bytes(KvHandle handle, std::uint64_t bytes);
    void release(KvHandle handle);

    std::uint64_t capacity_bytes() const noexcept { return capacity_bytes_; }
    std::uint64_t used_bytes() const;
    std::size_t free_pages() const;

private:
    DeviceId device_{};
    std::uint32_t page_bytes_{};
    std::uint64_t capacity_bytes_{};
    mutable std::mutex mu_;
    std::vector<std::uint32_t> free_pages_;
    std::unordered_map<KvHandle, KvAllocation> allocations_;
    KvHandle next_{1};
};

} // namespace rawrxd::swarm48
