// ============================================================================
// VramStreamingController.cpp — 24 GiB hard-residency / unlimited-model streaming
// ============================================================================
#include "VramStreamingController.hpp"
#include "NVMeStream.h"
#include "ElasticResidencyManager.hpp"
#include <algorithm>
#include <chrono>

namespace Deep2 {

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------
VramStreamingController::VramStreamingController() = default;

VramStreamingController::~VramStreamingController() = default;

// ---------------------------------------------------------------------------
// Controls: lock / unlock / set
// ---------------------------------------------------------------------------
void VramStreamingController::lockResidency() {
    lockState_.store(ResidencyLockState::Locked, std::memory_order_release);
}

void VramStreamingController::unlockResidency() {
    lockState_.store(ResidencyLockState::Unlocked, std::memory_order_release);
}

bool VramStreamingController::isLocked() const noexcept {
    return lockState_.load(std::memory_order_acquire) == ResidencyLockState::Locked;
}

void VramStreamingController::setVramCeilingGiB(uint32_t gib) {
    vramCeilingBytes_.store(static_cast<uint64_t>(gib) * 1024ull * 1024ull * 1024ull,
                            std::memory_order_release);
}

uint64_t VramStreamingController::vramCeilingBytes() const noexcept {
    return vramCeilingBytes_.load(std::memory_order_acquire);
}

void VramStreamingController::setHostSpillEnabled(bool enable) {
    hostSpillEnabled_.store(enable, std::memory_order_release);
}

bool VramStreamingController::isHostSpillEnabled() const noexcept {
    return hostSpillEnabled_.load(std::memory_order_acquire);
}

void VramStreamingController::setSpillTier(SpillTier tier) {
    spillTier_.store(tier, std::memory_order_release);
}

SpillTier VramStreamingController::spillTier() const noexcept {
    return spillTier_.load(std::memory_order_acquire);
}

// ---------------------------------------------------------------------------
// Measured per-token streaming
// ---------------------------------------------------------------------------
void VramStreamingController::setTokenBytesLimit(uint64_t bytes) {
    tokenBytesLimit_.store(bytes, std::memory_order_release);
}

uint64_t VramStreamingController::tokenBytesLimit() const noexcept {
    return tokenBytesLimit_.load(std::memory_order_acquire);
}

void VramStreamingController::beginTokenMeasurement(uint64_t tokenIndex) {
    std::lock_guard<std::mutex> lock(mtx_);
    currentTokenIndex_      = tokenIndex;
    currentTokenBytesMoved_ = 0;
    currentTokenLimitHit_   = false;
}

void VramStreamingController::recordBytesMoved(uint64_t bytes) {
    std::lock_guard<std::mutex> lock(mtx_);
    currentTokenBytesMoved_ += bytes;
    const uint64_t limit = tokenBytesLimit_.load(std::memory_order_acquire);
    if (limit > 0 && currentTokenBytesMoved_ > limit) {
        currentTokenLimitHit_ = true;
    }
}

bool VramStreamingController::endTokenMeasurement(uint64_t& outBytesMoved) {
    std::lock_guard<std::mutex> lock(mtx_);
    outBytesMoved = currentTokenBytesMoved_;
    ++stats_.tokensMeasured;
    stats_.tokenBytesMovedSum += currentTokenBytesMoved_;
    if (currentTokenBytesMoved_ > stats_.tokenBytesMovedMax)
        stats_.tokenBytesMovedMax = currentTokenBytesMoved_;

    const uint64_t limit = tokenBytesLimit_.load(std::memory_order_acquire);
    bool hit = false;
    if (limit > 0 && currentTokenBytesMoved_ > limit) {
        ++stats_.tokenBytesLimitHits;
        hit = true;
    }
    return !hit; // returns false if limit was hit
}

// ---------------------------------------------------------------------------
// Bounded in-flight traffic
// ---------------------------------------------------------------------------
void VramStreamingController::setMaxInFlightBytes(uint64_t bytes) {
    maxInFlightBytes_.store(bytes, std::memory_order_release);
}

uint64_t VramStreamingController::maxInFlightBytes() const noexcept {
    return maxInFlightBytes_.load(std::memory_order_acquire);
}

bool VramStreamingController::requestInFlightBytes(uint64_t bytes, uint32_t timeoutMs) {
    if (bytes == 0) return true;
    std::unique_lock<std::mutex> lock(mtx_);
    const uint64_t maxBytes = maxInFlightBytes_.load(std::memory_order_acquire);
    if (maxBytes == 0) {
        // unlimited
        inFlightBytes_ += bytes;
        updateInFlightPeakLocked();
        return true;
    }

    if (timeoutMs == 0) {
        if (inFlightBytes_ + bytes > maxBytes) {
            ++stats_.inFlightWaits;
            inFlightCv_.wait(lock, [this, bytes, maxBytes] {
                return inFlightBytes_ + bytes <= maxBytes;
            });
        }
        inFlightBytes_ += bytes;
        updateInFlightPeakLocked();
        return true;
    }

    // Timed wait
    bool ok = true;
    if (inFlightBytes_ + bytes > maxBytes) {
        ++stats_.inFlightWaits;
        ok = inFlightCv_.wait_for(lock, std::chrono::milliseconds(timeoutMs),
                                  [this, bytes, maxBytes] {
                                      return inFlightBytes_ + bytes <= maxBytes;
                                  });
    }
    if (ok) {
        inFlightBytes_ += bytes;
        updateInFlightPeakLocked();
    }
    return ok;
}

void VramStreamingController::releaseInFlightBytes(uint64_t bytes) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (bytes > inFlightBytes_) inFlightBytes_ = 0;
    else inFlightBytes_ -= bytes;
    inFlightCv_.notify_all();
}

// ---------------------------------------------------------------------------
// Tensor residency orchestration
// ---------------------------------------------------------------------------
void VramStreamingController::registerTensor(const std::string& name,
                                              uint64_t bytes,
                                              int priority) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto& rec = tensors_[name];
    if (rec.bytes == 0) rec.bytes = bytes; // preserve if already known
    rec.priority = priority;
}

bool VramStreamingController::requestResident(const std::string& name) {
    std::lock_guard<std::mutex> lock(mtx_);
    if (lockState_.load(std::memory_order_acquire) == ResidencyLockState::Locked) {
        ++stats_.lockEnforcedBlocks;
        ++stats_.prefetchDenied;
        return false;
    }

    auto it = tensors_.find(name);
    if (it == tensors_.end()) {
        ++stats_.prefetchDenied;
        return false;
    }
    auto& rec = it->second;
    if (rec.resident) {
        ++stats_.prefetchApproved; // already resident counts as immediate approval
        rec.lastToken = currentTokenIndex_;
        return true;
    }

    const uint64_t ceiling = vramCeilingBytes_.load(std::memory_order_acquire);
    uint64_t needed = rec.bytes;

    // If adding this tensor would exceed the ceiling, we must make room.
    if (vramUsedBytes_ + needed > ceiling) {
        if (!tryMakeRoomLocked(needed)) {
            ++stats_.prefetchDenied;
            return false;
        }
    }

    // Per-token limit check
    const uint64_t tokLimit = tokenBytesLimit_.load(std::memory_order_acquire);
    if (tokLimit > 0 && currentTokenBytesMoved_ + needed > tokLimit) {
        ++stats_.prefetchDenied;
        return false;
    }

    ++stats_.prefetchApproved;
    // Mark as logically requested; transfer provider will call markResident()
    rec.lastToken = currentTokenIndex_;
    return true;
}

void VramStreamingController::markResident(const std::string& name) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = tensors_.find(name);
    if (it == tensors_.end()) return;
    auto& rec = it->second;
    if (rec.resident) return; // idempotent
    if (rec.spilled) {
        // Moving from spill back to VRAM
        switch (spillTier_.load(std::memory_order_acquire)) {
            case SpillTier::HostRAM:  hostRamUsed_  -= std::min(hostRamUsed_,  rec.bytes); break;
            case SpillTier::HostNVMe: hostNvmeUsed_ -= std::min(hostNvmeUsed_, rec.bytes); break;
            default: break;
        }
        rec.spilled = false;
    }
    rec.resident = true;
    vramUsedBytes_ += rec.bytes;
    updateVramPeakLocked();

    // Update elastic manager if attached
    if (elasticMgr_) {
        elasticMgr_->markResident(name, ResidencyTier::VRAM, rec.bytes);
    }
}

bool VramStreamingController::evict(const std::string& name) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = tensors_.find(name);
    if (it == tensors_.end()) return false;
    auto& rec = it->second;
    if (!rec.resident && !rec.spilled) return false;

    ++stats_.evictRequests;

    if (rec.resident) {
        vramUsedBytes_ -= std::min(vramUsedBytes_, rec.bytes);
        rec.resident = false;
    }

    if (isHostSpillEnabled()) {
        switch (spillTier_.load(std::memory_order_acquire)) {
            case SpillTier::HostRAM:
                rec.spilled = true;
                hostRamUsed_ += rec.bytes;
                updateHostPeakLocked();
                break;
            case SpillTier::HostNVMe:
                rec.spilled = true;
                hostNvmeUsed_ += rec.bytes;
                break;
            default:
                rec.spilled = false;
                break;
        }
        ++stats_.spillEvictions;
    }

    ++stats_.evictApproved;
    ++stats_.ceilingEnforcedEvictions;
    return true;
}

bool VramStreamingController::makeRoom(uint64_t requiredBytes) {
    std::lock_guard<std::mutex> lock(mtx_);
    return tryMakeRoomLocked(requiredBytes);
}

bool VramStreamingController::isResident(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = tensors_.find(name);
    return (it != tensors_.end()) && it->second.resident;
}

uint64_t VramStreamingController::tensorBytes(const std::string& name) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = tensors_.find(name);
    return (it != tensors_.end()) ? it->second.bytes : 0;
}

uint64_t VramStreamingController::vramUsedBytes() const noexcept {
    std::lock_guard<std::mutex> lock(mtx_);
    return vramUsedBytes_;
}

uint64_t VramStreamingController::hostSpillBytes() const noexcept {
    std::lock_guard<std::mutex> lock(mtx_);
    return hostRamUsed_ + hostNvmeUsed_;
}

VramStreamingStats VramStreamingController::stats() const {
    std::lock_guard<std::mutex> lock(mtx_);
    VramStreamingStats s = stats_;
    s.vramCeilingBytes = vramCeilingBytes_.load(std::memory_order_acquire);
    s.vramUsedBytes    = vramUsedBytes_;
    s.vramPeakBytes    = vramPeakBytes_;
    s.hostRamUsedBytes = hostRamUsed_;
    s.hostRamPeakBytes = hostRamPeak_;
    s.hostNvmeUsedBytes = hostNvmeUsed_;
    s.inFlightBytes    = inFlightBytes_;
    s.inFlightBytesMax = inFlightPeak_;
    s.tokensMeasured   = stats_.tokensMeasured;
    return s;
}

void VramStreamingController::reset() {
    std::lock_guard<std::mutex> lock(mtx_);
    tensors_.clear();
    vramUsedBytes_   = 0;
    vramPeakBytes_   = 0;
    hostRamUsed_     = 0;
    hostRamPeak_     = 0;
    hostNvmeUsed_    = 0;
    inFlightBytes_   = 0;
    inFlightPeak_    = 0;
    currentTokenBytesMoved_ = 0;
    currentTokenLimitHit_   = false;
    stats_ = VramStreamingStats{};
}

// ---------------------------------------------------------------------------
// Integration hooks
// ---------------------------------------------------------------------------
void VramStreamingController::attachNvmeStream(NVMeStream* stream) {
    nvmeStream_ = stream;
}

void VramStreamingController::attachElasticManager(ElasticResidencyManager* mgr) {
    elasticMgr_ = mgr;
}

std::vector<TensorResidencyInfo> VramStreamingController::snapshot() const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<TensorResidencyInfo> out;
    out.reserve(tensors_.size());
    for (const auto& kv : tensors_) {
        TensorResidencyInfo info;
        info.name      = kv.first;
        info.bytes     = kv.second.bytes;
        info.resident  = kv.second.resident;
        info.spilled   = kv.second.spilled;
        info.lastToken = kv.second.lastToken;
        info.priority  = kv.second.priority;
        out.push_back(std::move(info));
    }
    return out;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------
bool VramStreamingController::tryMakeRoomLocked(uint64_t requiredBytes) {
    const uint64_t ceiling = vramCeilingBytes_.load(std::memory_order_acquire);
    if (vramUsedBytes_ + requiredBytes <= ceiling) return true;

    // Collect evictable candidates: resident tensors, sorted by lastToken (LRU)
    struct Candidate {
        uint64_t lastToken;
        std::string name;
        uint64_t bytes;
    };
    std::vector<Candidate> candidates;
    candidates.reserve(tensors_.size());
    for (auto& kv : tensors_) {
        if (kv.second.resident && kv.second.priority <= 0) {
            candidates.push_back({kv.second.lastToken, kv.first, kv.second.bytes});
        }
    }
    std::sort(candidates.begin(), candidates.end(),
              [](const Candidate& a, const Candidate& b) {
                  return a.lastToken < b.lastToken;
              });

    uint64_t freed = 0;
    for (const auto& c : candidates) {
        auto it = tensors_.find(c.name);
        if (it == tensors_.end()) continue;
        auto& rec = it->second;
        if (!rec.resident) continue;

        // Evict
        vramUsedBytes_ -= std::min(vramUsedBytes_, rec.bytes);
        rec.resident = false;

        if (isHostSpillEnabled()) {
            switch (spillTier_.load(std::memory_order_acquire)) {
                case SpillTier::HostRAM:
                    rec.spilled = true;
                    hostRamUsed_ += rec.bytes;
                    break;
                case SpillTier::HostNVMe:
                    rec.spilled = true;
                    hostNvmeUsed_ += rec.bytes;
                    break;
                default:
                    rec.spilled = false;
                    break;
            }
            ++stats_.spillEvictions;
        }

        ++stats_.ceilingEnforcedEvictions;
        freed += rec.bytes;
        if (vramUsedBytes_ + requiredBytes <= ceiling) break;
    }

    // If even after evicting everything we still can't fit, and spill is not enabled,
    // we fail. With spill enabled, we trust host memory is infinite.
    if (!isHostSpillEnabled() && (vramUsedBytes_ + requiredBytes > ceiling)) {
        return false;
    }
    return true;
}

void VramStreamingController::updateVramPeakLocked() {
    if (vramUsedBytes_ > vramPeakBytes_) vramPeakBytes_ = vramUsedBytes_;
}

void VramStreamingController::updateHostPeakLocked() {
    if (hostRamUsed_ > hostRamPeak_) hostRamPeak_ = hostRamUsed_;
}

void VramStreamingController::updateInFlightPeakLocked() {
    if (inFlightBytes_ > inFlightPeak_) inFlightPeak_ = inFlightBytes_;
}

} // namespace Deep2
