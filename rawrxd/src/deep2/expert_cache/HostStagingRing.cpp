#include "HostStagingRing.h"
#include <algorithm>

namespace rawrxd::deep2 {

size_t HostStagingRing::alignUp(size_t v, size_t a) {
    if (a <= 1) return v;
    const size_t r = v % a;
    return r ? (v + (a - r)) : v;
}

void HostStagingRing::reset(size_t capacityBytes, size_t alignmentBytes) {
    std::lock_guard<std::mutex> lock(mu_);
    capacity_ = capacityBytes;
    alignment_ = std::max<size_t>(1, alignmentBytes);
    head_ = tail_ = used_ = 0;
    q_.clear();
}

StagingSlice HostStagingRing::reserve(size_t bytes, uint64_t ticket) {
    std::lock_guard<std::mutex> lock(mu_);
    if (!ticket || !bytes || !capacity_) return {};
    const size_t n = alignUp(bytes, alignment_);
    if (n > capacity_ || n > capacity_ - used_) return {};

    // Empty ring: begin at zero for deterministic reuse.
    if (q_.empty()) head_ = tail_ = 0;

    size_t off = head_;
    if (head_ >= tail_) {
        if (head_ + n <= capacity_) {
            off = head_;
            head_ = (head_ + n == capacity_) ? 0 : head_ + n;
        } else if (n <= tail_) {
            off = 0;
            head_ = n;
        } else return {};
    } else {
        if (head_ + n <= tail_) {
            off = head_;
            head_ += n;
        } else return {};
    }

    used_ += n;
    StagingSlice s{ticket, off, n};
    q_.push_back(Node{s, false});
    return s;
}

bool HostStagingRing::complete(uint64_t ticket) {
    std::lock_guard<std::mutex> lock(mu_);
    for (auto& n : q_) {
        if (n.s.ticket == ticket) { n.done = true; reclaimLocked(); return true; }
    }
    return false;
}

void HostStagingRing::reclaimLocked() {
    while (!q_.empty() && q_.front().done) {
        const auto s = q_.front().s;
        if (used_ >= s.bytes) used_ -= s.bytes; else used_ = 0;
        tail_ = (s.offset + s.bytes >= capacity_) ? 0 : (s.offset + s.bytes);
        q_.pop_front();
    }
    if (q_.empty()) head_ = tail_ = 0;
}

size_t HostStagingRing::used() const { std::lock_guard<std::mutex> lock(mu_); return used_; }
size_t HostStagingRing::freeBytes() const { std::lock_guard<std::mutex> lock(mu_); return capacity_ - used_; }
size_t HostStagingRing::inFlight() const { std::lock_guard<std::mutex> lock(mu_); return q_.size(); }

} // namespace rawrxd::deep2
