#pragma once
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>
#include <atomic>

namespace rawrxd {

class ForwardDepthGuard {
public:
    explicit ForwardDepthGuard(uint32_t limit = 8) noexcept;
    ~ForwardDepthGuard() noexcept;
    ForwardDepthGuard(const ForwardDepthGuard&) = delete;
    ForwardDepthGuard& operator=(const ForwardDepthGuard&) = delete;
    bool ok() const noexcept { return ok_; }
    uint32_t depth() const noexcept { return depth_; }
    static uint32_t currentDepth() noexcept;
private:
    bool ok_{};
    uint32_t depth_{};
    static thread_local uint32_t tlsDepth_;
};

class HeapScratchArena {
public:
    explicit HeapScratchArena(size_t reserveBytes = 0);
    void reset() noexcept { cursor_ = 0; }
    void reserve(size_t bytes);
    void* alloc(size_t bytes, size_t alignment = 64);
    template<class T> T* allocArray(size_t count, size_t alignment = alignof(T)) {
        if (count > (SIZE_MAX / sizeof(T))) return nullptr;
        return static_cast<T*>(alloc(count * sizeof(T), alignment));
    }
    size_t capacity() const noexcept { return storage_.size(); }
    size_t used() const noexcept { return cursor_; }
private:
    std::vector<std::uint8_t> storage_;
    size_t cursor_{};
};

struct StackSafetyTelemetry {
    std::atomic<uint64_t> forwardEntries{0};
    std::atomic<uint64_t> recursionRejects{0};
    std::atomic<uint64_t> scratchAllocFailures{0};
    std::atomic<uint64_t> maxObservedDepth{0};
};

bool updateMaxDepth(StackSafetyTelemetry& t, uint64_t depth) noexcept;

} // namespace rawrxd
