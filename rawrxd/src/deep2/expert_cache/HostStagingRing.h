#pragma once
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>

namespace rawrxd::deep2 {

struct StagingSlice {
    uint64_t ticket = 0;
    size_t offset = 0;
    size_t bytes = 0;
    explicit operator bool() const noexcept { return ticket != 0 && bytes != 0; }
};

// Metadata-only circular allocator for a persistently mapped host-visible staging buffer.
// Completion may be reported out of order; storage is reclaimed in submission order.
class HostStagingRing final {
public:
    HostStagingRing() = default;
    HostStagingRing(size_t capacityBytes, size_t alignmentBytes = 256) { reset(capacityBytes, alignmentBytes); }

    void reset(size_t capacityBytes, size_t alignmentBytes = 256);
    StagingSlice reserve(size_t bytes, uint64_t ticket);
    bool complete(uint64_t ticket);
    size_t capacity() const noexcept { return capacity_; }
    size_t used() const;
    size_t freeBytes() const;
    size_t inFlight() const;

private:
    struct Node { StagingSlice s{}; bool done = false; };
    static size_t alignUp(size_t v, size_t a);
    void reclaimLocked();

    mutable std::mutex mu_;
    size_t capacity_ = 0;
    size_t alignment_ = 256;
    size_t head_ = 0;
    size_t tail_ = 0;
    size_t used_ = 0;
    std::deque<Node> q_;
};

} // namespace rawrxd::deep2
