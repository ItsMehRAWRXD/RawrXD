#pragma once
#include <cstdint>
#include <mutex>
#include <limits>
namespace rawrxd::mla {
class CacheTransaction {
public:
    struct Ticket { uint64_t generation = 0; uint64_t begin = 0; uint64_t count = 0; };
    explicit CacheTransaction(uint64_t capacity) : capacity_(capacity) {}
    bool begin(uint64_t count, Ticket& out) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (active_ || !count || committed_ > capacity_ || count > capacity_ - committed_ ||
            generation_ == std::numeric_limits<uint64_t>::max()) return false;
        active_ = true;
        pending_ = { ++generation_, committed_, count };
        out = pending_; return true;
    }
    bool commit(const Ticket& ticket) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!matches(ticket)) return false;
        committed_ += pending_.count; pending_ = {}; active_ = false; return true;
    }
    bool rollback(const Ticket& ticket) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!matches(ticket)) return false;
        pending_ = {}; active_ = false; return true;
    }
    uint64_t committed() const { std::lock_guard<std::mutex> lock(mutex_); return committed_; }
private:
    bool matches(const Ticket& t) const {
        return active_ && t.generation == pending_.generation && t.begin == pending_.begin && t.count == pending_.count;
    }
    mutable std::mutex mutex_;
    uint64_t capacity_ = 0, committed_ = 0, generation_ = 0;
    bool active_ = false;
    Ticket pending_{};
};
}