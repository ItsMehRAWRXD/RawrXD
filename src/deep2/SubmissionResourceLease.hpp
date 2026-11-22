// SubmissionResourceLease.hpp — completion-bound resource leases.
//
// A resource (GPU staging buffer, weight pin, descriptor set, scratch, REAP
// expert) cannot be released merely because the CPU dispatch returned; its GPU
// consumer must have completed first. Release authorization is coordinated with
// the OneShotOwner completion transition; this component does not independently
// prove GPU completion.
#pragma once

#include "SubmissionLifecycle.hpp"

#include <cstddef>
#include <memory>
#include <mutex>
#include <vector>

namespace RawrXD {
namespace Deep2 {

class SubmissionResourceLease final {
public:
    using Ticket = SubmissionLifecycle::Ticket;
    using Resource = std::shared_ptr<const void>;

    bool Attach(Ticket ticket, Resource resource) {
        if (!ticket || !resource) return false;
        std::lock_guard<std::mutex> lock(mutex_);
        if (sealed_) return false;
        if (active_ && !Matches(ticket)) return false;
        try {
            resources_.push_back(std::move(resource));
            active_ = ticket;
            return true;
        } catch (...) {
            return false;
        }
    }

    bool Seal(Ticket ticket) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!Matches(ticket) || sealed_) return false;
        sealed_ = true;
        return true;
    }

    // Invoke only after an authoritative completion transition for this ticket.
    bool ReleaseConfirmed(Ticket ticket) {
        std::vector<Resource> released;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!Matches(ticket) || !sealed_) return false;
            released.swap(resources_);
            active_ = {};
            sealed_ = false;
        }
        released.clear();   // destructors run outside the lease mutex
        return true;
    }

    // Only for work proven never submitted.
    bool ReleaseUnsubmitted(Ticket ticket) {
        std::vector<Resource> released;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!Matches(ticket) || sealed_) return false;
            released.swap(resources_);
            active_ = {};
        }
        released.clear();
        return true;
    }

    size_t Count() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return resources_.size();
    }

private:
    bool Matches(Ticket t) const noexcept {
        return bool(t) && t.generation == active_.generation && t.acquisition == active_.acquisition;
    }

    mutable std::mutex mutex_;
    Ticket active_{};
    bool sealed_ = false;
    std::vector<Resource> resources_;
};

} // namespace Deep2
} // namespace RawrXD