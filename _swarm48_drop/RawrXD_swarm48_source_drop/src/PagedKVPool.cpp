#include "rawrxd/swarm48/PagedKVPool.hpp"

namespace rawrxd::swarm48 {

PagedKVPool::PagedKVPool(DeviceId device, KvPoolConfig cfg)
    : device_(device), page_bytes_(std::max<std::uint32_t>(cfg.page_bytes, 4096u)) {
    const auto pages = cfg.total_bytes / page_bytes_;
    capacity_bytes_ = pages * page_bytes_;
    free_pages_.reserve(static_cast<std::size_t>(pages));
    for (std::uint32_t i = 0; i < pages; ++i) free_pages_.push_back(i);
}

KvHandle PagedKVPool::create(AgentId agent) {
    std::lock_guard lock(mu_);
    const auto h = next_++;
    allocations_.emplace(h, KvAllocation{h, agent, device_, {}});
    return h;
}

bool PagedKVPool::ensure_bytes(KvHandle handle, std::uint64_t bytes) {
    std::lock_guard lock(mu_);
    auto it = allocations_.find(handle);
    if (it == allocations_.end()) return false;
    const auto need = static_cast<std::size_t>((bytes + page_bytes_ - 1) / page_bytes_);
    if (it->second.pages.size() >= need) return true;
    const auto additional = need - it->second.pages.size();
    if (free_pages_.size() < additional) return false;
    for (std::size_t n = 0; n < additional; ++n) {
        it->second.pages.push_back(free_pages_.back());
        free_pages_.pop_back();
    }
    return true;
}

void PagedKVPool::trim_to_bytes(KvHandle handle, std::uint64_t bytes) {
    std::lock_guard lock(mu_);
    auto it = allocations_.find(handle);
    if (it == allocations_.end()) return;
    const auto keep = static_cast<std::size_t>((bytes + page_bytes_ - 1) / page_bytes_);
    while (it->second.pages.size() > keep) {
        free_pages_.push_back(it->second.pages.back());
        it->second.pages.pop_back();
    }
}

void PagedKVPool::release(KvHandle handle) {
    std::lock_guard lock(mu_);
    auto it = allocations_.find(handle);
    if (it == allocations_.end()) return;
    free_pages_.insert(free_pages_.end(), it->second.pages.begin(), it->second.pages.end());
    allocations_.erase(it);
}

std::uint64_t PagedKVPool::used_bytes() const {
    std::lock_guard lock(mu_);
    std::uint64_t pages = 0;
    for (const auto& [_, a] : allocations_) pages += a.pages.size();
    return pages * page_bytes_;
}

std::size_t PagedKVPool::free_pages() const {
    std::lock_guard lock(mu_);
    return free_pages_.size();
}

} // namespace rawrxd::swarm48
