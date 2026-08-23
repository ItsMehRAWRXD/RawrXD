// ============================================================================
// ResidencyLease.cpp — Lease Implementation
// ============================================================================

#include "ResidencyLease.hpp"
#include <cstdio>
#include <string>

namespace Deep2 {

// ============================================================================
// Move Semantics
// ============================================================================
ResidencyLease::ResidencyLease(ResidencyLease&& other) noexcept {
    MoveFrom(std::move(other));
}

ResidencyLease& ResidencyLease::operator=(ResidencyLease&& other) noexcept {
    if (this != &other) {
        Invalidate();
        MoveFrom(std::move(other));
    }
    return *this;
}

void ResidencyLease::MoveFrom(ResidencyLease&& other) noexcept {
    leaseId_ = other.leaseId_;
    tensorName_ = std::move(other.tensorName_);
    data_ = other.data_;
    mappedOffset_ = other.mappedOffset_;
    mappedBytes_ = other.mappedBytes_;
    requestedBytes_ = other.requestedBytes_;
    generation_ = other.generation_;
    state_ = other.state_;
    manager_ = other.manager_;

    other.leaseId_ = 0;
    other.data_ = nullptr;
    other.mappedOffset_ = 0;
    other.mappedBytes_ = 0;
    other.requestedBytes_ = 0;
    other.generation_ = 0;
    other.state_ = LeaseState::Invalid;
    other.manager_ = nullptr;
}

// ============================================================================
// Acquisition
// ============================================================================
bool ResidencyLease::Acquire(ResidencyManager& manager,
                              const std::string& tensorName,
                              size_t expectedBytes) {
    // Cannot acquire if already active
    if (state_ == LeaseState::Active) {
        fprintf(stderr, "[RESIDENCY_FAIL] Lease %llu: already active for '%s', cannot acquire '%s'\n",
                (unsigned long long)leaseId_, tensorName_.c_str(), tensorName.c_str());
        return false;
    }

    Reset();

    // TODO: delegate to ResidencyManager once implemented
    // For now, mark as failed (manager not yet available)
    (void)manager;
    (void)expectedBytes;

    tensorName_ = tensorName;
    leaseId_ = nextLeaseId_++;
    state_ = LeaseState::Invalid;

    // Placeholder: real implementation will call manager.AcquireTensor()
    // and populate data_, mappedOffset_, mappedBytes_, generation_

    return false; // Stub: will succeed once manager is wired
}

// ============================================================================
// Validation
// ============================================================================
bool ResidencyLease::IsValid() const {
    if (state_ != LeaseState::Active) return false;
    if (!data_) return false;
    if (tensorName_.empty()) return false;

    // TODO: generation check against manager once implemented
    // if (manager_ && manager_->GetTensorGeneration(tensorName_) != generation_) {
    //     const_cast<ResidencyLease*>(this)->state_ = LeaseState::Stale;
    //     return false;
    // }

    return true;
}

// ============================================================================
// Release
// ============================================================================
bool ResidencyLease::Release() {
    if (state_ != LeaseState::Active) {
        // Idempotent: already released or never active
        return false;
    }

    // TODO: notify manager once implemented
    // if (manager_) {
    //     manager_->ReleaseLease(*this);
    // }

    state_ = LeaseState::Released;
    data_ = nullptr;
    generation_ = 0;
    return true;
}

// ============================================================================
// Invalidate
// ============================================================================
void ResidencyLease::Invalidate() {
    if (state_ == LeaseState::Active) {
        Release();
    }
    Reset();
}

void ResidencyLease::Reset() {
    leaseId_ = 0;
    tensorName_.clear();
    data_ = nullptr;
    mappedOffset_ = 0;
    mappedBytes_ = 0;
    requestedBytes_ = 0;
    generation_ = 0;
    state_ = LeaseState::Invalid;
    manager_ = nullptr;
}

// ============================================================================
// Diagnostics
// ============================================================================
const char* ResidencyLease::StateString() const {
    switch (state_) {
        case LeaseState::Invalid:  return "Invalid";
        case LeaseState::Active:   return "Active";
        case LeaseState::Released: return "Released";
        case LeaseState::Stale:    return "Stale";
        case LeaseState::Evicted:  return "Evicted";
        default:                   return "Unknown";
    }
}

void ResidencyLease::Print() const {
    printf("ResidencyLease[%llu] tensor='%s' state=%s data=%p "
           "mapped=%zu requested=%zu generation=%llu\n",
           (unsigned long long)leaseId_, tensorName_.c_str(),
           StateString(), data_,
           mappedBytes_, requestedBytes_,
           (unsigned long long)generation_);
}

} // namespace Deep2
