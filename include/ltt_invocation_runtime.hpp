#pragma once
// RawrXD LTT: in-process, request-scoped execution with bounded resource leases.
// No network server or permanent tensor allocation is required by this scheduler.
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <utility>

namespace RawrXD::LTT {
struct TensorView {
    uint64_t storage_offset = 0;
    uint64_t byte_length = 0;
    uint32_t quant_type = 0;
    uint32_t rows = 0;
    uint32_t columns = 0;
};

class ByteBudget {
public:
    explicit ByteBudget(uint64_t capacity) : capacity_(capacity) {
        if (!capacity) throw std::invalid_argument("LTT capacity must be nonzero");
    }
    ByteBudget(const ByteBudget&) = delete;
    ByteBudget& operator=(const ByteBudget&) = delete;

    class Lease {
    public:
        Lease() = default;
        Lease(ByteBudget* owner, uint64_t bytes) : owner_(owner), bytes_(bytes) {}
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;
        Lease(Lease&& other) noexcept
            : owner_(std::exchange(other.owner_, nullptr)),
              bytes_(std::exchange(other.bytes_, 0)) {}
        Lease& operator=(Lease&& other) noexcept {
            if (this != &other) {
                release();
                owner_ = std::exchange(other.owner_, nullptr);
                bytes_ = std::exchange(other.bytes_, 0);
            }
            return *this;
        }
        ~Lease() { release(); }
        void release() noexcept {
            if (!owner_) return;
            owner_->release(bytes_);
            owner_ = nullptr;
            bytes_ = 0;
        }
        uint64_t bytes() const noexcept { return bytes_; }
    private:
        ByteBudget* owner_ = nullptr;
        uint64_t bytes_ = 0;
    };

    Lease acquire(uint64_t bytes) {
        if (!bytes || bytes > capacity_)
            throw std::invalid_argument("LTT lease outside byte budget");
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock, [&] { return bytes <= capacity_ - used_; });
        used_ += bytes;
        if (used_ > peak_) peak_ = used_;
        return Lease(this, bytes);
    }

    uint64_t used() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return used_;
    }
    uint64_t peak() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return peak_;
    }
private:
    void release(uint64_t bytes) noexcept {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            used_ -= bytes;
        }
        cv_.notify_all();
    }
    const uint64_t capacity_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    uint64_t used_ = 0;
    uint64_t peak_ = 0;
};

// Caller supplies actual storage fetch and Vulkan submission. Lease MUST remain
// alive until GPU completion (fence/timeline), not merely queue submission.
// The callback is synchronous by contract and must wait for GPU completion.
template<class FetchAndDispatch>
void invoke(ByteBudget& budget, const TensorView& tensor,
            uint64_t scratch_bytes, FetchAndDispatch&& fetch_and_dispatch) {
    if (!tensor.byte_length) throw std::invalid_argument("empty LTT tensor");
    auto lease = budget.acquire(scratch_bytes);
    std::forward<FetchAndDispatch>(fetch_and_dispatch)(tensor);
}
} // namespace RawrXD::LTT
