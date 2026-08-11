#pragma once
// =============================================================================
// Module 2: Portable Cancellation Token
// Replaces C++20 std::stop_source / std::stop_token with C++14 atomics + CV.
// No external dependencies.
// =============================================================================

#include <atomic>
#include <condition_variable>
#include <mutex>

// --- CancelToken ---
// Read side. Lightweight — just a pointer to shared atomic + CV.
// Copyable, thread-safe.
class CancelToken {
public:
    CancelToken() : flag_(nullptr), cv_(nullptr), mtx_(nullptr) {}

    explicit CancelToken(const std::atomic<bool>* flag,
                         const std::condition_variable* cv,
                         const std::mutex* mtx)
        : flag_(flag), cv_(cv), mtx_(mtx) {}

    bool stopRequested() const {
        return flag_ != nullptr && flag_->load(std::memory_order_acquire);
    }

    bool stopPossible() const {
        return flag_ != nullptr;
    }

    // Block until stop is requested or predicate becomes true.
    // Returns true if predicate satisfied, false if cancelled.
    template <typename Predicate>
    bool waitFor(Predicate pred) const {
        if (!mtx_ || !cv_) return pred();
        std::unique_lock<std::mutex> lk(*mtx_);
        cv_->wait(lk, [&]() {
            return stopRequested() || pred();
        });
        return !stopRequested() && pred();
    }

private:
    const std::atomic<bool>*          flag_;
    const std::condition_variable*    cv_;
    const std::mutex*                 mtx_;
};

// --- CancelSource ---
// Write side. Owns the atomic flag, CV, and mutex.
// Non-copyable, NON-MOVABLE — CancelToken holds raw pointers into this object.
class CancelSource {
public:
    CancelSource() : flag_(false) {}

    CancelSource(const CancelSource&) = delete;
    CancelSource& operator=(const CancelSource&) = delete;

    // Deleted move operations — CancelToken contains raw pointers to our members.
    // Moving would leave existing tokens dangling.
    CancelSource(CancelSource&&) = delete;
    CancelSource& operator=(CancelSource&&) = delete;

    bool requestStop() {
        bool expected = false;
        if (flag_.compare_exchange_strong(expected, true,
                std::memory_order_acq_rel)) {
            cv_.notify_all();
            return true;
        }
        return false;
    }

    bool stopRequested() const {
        return flag_.load(std::memory_order_acquire);
    }

    CancelToken getToken() const {
        return CancelToken(&flag_, &cv_, &mtx_);
    }

private:
    std::atomic<bool>           flag_;
    std::condition_variable     cv_;
    std::mutex                  mtx_;
};