// SubmissionLifecycle.hpp — Deep2 explicit submission state machine.
//
// Replaces independent Boolean flags with one coherent state machine so
// admission, submission, completion and cleanup cannot become inconsistent
// under concurrency. Every transition validates the acquisition ticket and its
// device generation.
#pragma once

#include <cstdint>
#include <limits>
#include <mutex>

namespace RawrXD {
namespace Deep2 {

class SubmissionLifecycle final {
public:
    enum class State {
        Idle,
        Acquired,
        Submitting,
        Submitted,
        Quarantined
    };

    struct Ticket {
        uint64_t generation = 0;
        uint64_t acquisition = 0;

        explicit operator bool() const noexcept {
            return generation != 0 && acquisition != 0;
        }
    };

    struct Snapshot {
        State state = State::Idle;
        uint64_t generation = 0;
        uint64_t acquisition = 0;
        bool admissionBlocked = true;
        bool cleanupActive = false;
        bool terminal = false;
    };

    SubmissionLifecycle() = default;
    SubmissionLifecycle(const SubmissionLifecycle&) = delete;
    SubmissionLifecycle& operator=(const SubmissionLifecycle&) = delete;

    bool OpenGeneration() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (terminal_ || cleanupActive_ || state_ != State::Idle || !admissionBlocked_)
            return false;
        if (generation_ == std::numeric_limits<uint64_t>::max()) { terminal_ = true; return false; }
        ++generation_;
        admissionBlocked_ = false;
        return true;
    }

    Ticket Acquire() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (terminal_ || admissionBlocked_ || cleanupActive_ || state_ != State::Idle || generation_ == 0)
            return {};
        if (sequence_ == std::numeric_limits<uint64_t>::max()) { admissionBlocked_ = true; terminal_ = true; return {}; }
        active_ = {generation_, ++sequence_};
        state_ = State::Acquired;
        return active_;
    }

    bool BeginSubmit(Ticket ticket) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!Matches(ticket) || state_ != State::Acquired || terminal_) return false;
        state_ = State::Submitting;
        return true;
    }

    bool MarkSubmitted(Ticket ticket) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!Matches(ticket) || state_ != State::Submitting) return false;
        state_ = State::Submitted;
        return true;
    }

    bool CancelUnsubmitted(Ticket ticket) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!Matches(ticket) || state_ != State::Acquired) return false;
        ResetActive();
        return true;
    }

    // Use only when the submission outcome is uncertain, including device-lost.
    bool QuarantineSubmission(Ticket ticket) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!Matches(ticket) || (state_ != State::Submitting && state_ != State::Submitted)) return false;
        state_ = State::Quarantined;
        admissionBlocked_ = true;
        terminal_ = true;
        return true;
    }

    // Caller must possess real completion evidence for this exact submission.
    bool CompleteConfirmed(Ticket ticket) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!Matches(ticket) || state_ != State::Submitted) return false;
        ResetActive();
        return true;
    }

    bool BeginCleanup() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (cleanupActive_ || terminal_) return false;
        admissionBlocked_ = true;
        cleanupActive_ = true;
        return true;
    }

    bool CanDestroyResources() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return cleanupActive_ && admissionBlocked_ && state_ == State::Idle && !terminal_;
    }

    bool DeferCleanup() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!cleanupActive_) return false;
        cleanupActive_ = false;
        return true;
    }

    bool FinishCleanup() {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!cleanupActive_ || state_ != State::Idle || terminal_) return false;
        cleanupActive_ = false;
        admissionBlocked_ = true;
        return true;
    }

    Snapshot Inspect() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return {state_, generation_, active_.acquisition, admissionBlocked_, cleanupActive_, terminal_};
    }

private:
    bool Matches(Ticket t) const noexcept {
        return bool(t) && t.generation == active_.generation && t.acquisition == active_.acquisition;
    }
    void ResetActive() noexcept { active_ = {}; state_ = State::Idle; }

    mutable std::mutex mutex_;
    State state_ = State::Idle;
    uint64_t generation_ = 0;
    uint64_t sequence_ = 0;
    Ticket active_{};
    bool admissionBlocked_ = true;
    bool cleanupActive_ = false;
    bool terminal_ = false;
};

} // namespace Deep2
} // namespace RawrXD