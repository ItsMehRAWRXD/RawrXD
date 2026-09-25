#include "Deep2StackGuard.h"
#include <algorithm>
#include <new>

namespace rawrxd {
thread_local uint32_t ForwardDepthGuard::tlsDepth_ = 0;

ForwardDepthGuard::ForwardDepthGuard(uint32_t limit) noexcept {
    depth_ = ++tlsDepth_;
    ok_ = depth_ <= limit;
}
ForwardDepthGuard::~ForwardDepthGuard() noexcept {
    if (tlsDepth_) --tlsDepth_;
}
uint32_t ForwardDepthGuard::currentDepth() noexcept { return tlsDepth_; }

HeapScratchArena::HeapScratchArena(size_t reserveBytes) {
    if (reserveBytes) storage_.resize(reserveBytes);
}
void HeapScratchArena::reserve(size_t bytes) {
    if (bytes > storage_.size()) storage_.resize(bytes);
}
void* HeapScratchArena::alloc(size_t bytes, size_t alignment) {
    if (!bytes || !alignment || (alignment & (alignment - 1))) return nullptr;
    const size_t aligned = (cursor_ + alignment - 1) & ~(alignment - 1);
    if (aligned > SIZE_MAX - bytes) return nullptr;
    const size_t end = aligned + bytes;
    if (end > storage_.size()) {
        size_t target = std::max(end, storage_.empty() ? size_t(1 << 20) : storage_.size() * 2);
        try { storage_.resize(target); } catch (...) { return nullptr; }
    }
    void* p = storage_.data() + aligned;
    cursor_ = end;
    return p;
}

bool updateMaxDepth(StackSafetyTelemetry& t, uint64_t depth) noexcept {
    auto cur = t.maxObservedDepth.load(std::memory_order_relaxed);
    while (cur < depth && !t.maxObservedDepth.compare_exchange_weak(cur, depth, std::memory_order_relaxed)) {}
    return true;
}
} // namespace rawrxd
