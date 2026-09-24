// ============================================================================
// ElasticResidencyManager.cpp — Layer 0.1 real implementation
// ============================================================================
#include "ElasticResidencyManager.hpp"
#include <algorithm>
#include <numeric>

namespace Deep2 {

ElasticResidencyManager::ElasticResidencyManager() = default;
ElasticResidencyManager::~ElasticResidencyManager() = default;

void ElasticResidencyManager::registerTensor(const std::string& name, uint64_t bytes) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto& rec = tensors_[name];
    if (rec.bytes == 0) rec.bytes = bytes; // only set if not already known
}

void ElasticResidencyManager::reset() {
    std::lock_guard<std::mutex> lock(mtx_);
    tensors_.clear();
    layerTensorNames_.clear();
    stats_ = ElasticResidencyStats{};
    currentEpoch_ = 1;
    budget_.clear();
}

void ElasticResidencyManager::bumpEpoch() {
    ++currentEpoch_;
    if (currentEpoch_ == 0) currentEpoch_ = 1; // epoch 0 is sentinel
}

void ElasticResidencyManager::PredictLayerNeeds(uint32_t layer,
                                                 const std::vector<std::string>* names,
                                                 size_t count) {
    std::lock_guard<std::mutex> lock(mtx_);
    ++stats_.predictions;

    // Store expected tensor list for this layer
    auto& layerNames = layerTensorNames_[layer];
    layerNames.clear();
    if (names && count > 0) {
        layerNames.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            layerNames.push_back((*names)[i]);
        }
    }

    // Process each expected tensor
    for (const auto& name : layerNames) {
        ++stats_.tensorRequests;
        auto& rec = tensors_[name];
        rec.lastRequestEpoch = currentEpoch_;

        switch (rec.state) {
            case ResidencyState::Resident:
                ++stats_.alreadyResidentHits;
                rec.lastAccessEpoch = currentEpoch_;
                break;
            case ResidencyState::Prefetching:
                // Already in flight; will become Resident or Miss when provider reports back.
                break;
            case ResidencyState::Unknown:
            case ResidencyState::Evicted:
                // Need to request prefetch
                rec.state = ResidencyState::Requested;
                stats_.bytesRequested += rec.bytes;
                break;
            case ResidencyState::Requested:
            case ResidencyState::Evictable:
                // Already requested or evictable; no duplicate request.
                break;
        }
    }

    bumpEpoch();
}

double ElasticResidencyManager::PrefetchHitRatePct() const noexcept {
    std::lock_guard<std::mutex> lock(mtx_);
    const uint64_t total = stats_.prefetchHits + stats_.misses;
    return total ? 100.0 * static_cast<double>(stats_.prefetchHits) / static_cast<double>(total) : 0.0;
}

void ElasticResidencyManager::markResident(const std::string& tensorName,
                                            ResidencyTier tier,
                                            uint64_t bytes) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto& rec = tensors_[tensorName];
    rec.state = ResidencyState::Resident;
    rec.tier = tier;
    rec.bytes = bytes;
    rec.lastAccessEpoch = currentEpoch_;
    ++stats_.promotions;
    stats_.bytesPromoted += bytes;

    switch (tier) {
        case ResidencyTier::VRAM:  stats_.vramResidentBytes += bytes; break;
        case ResidencyTier::RAM:   stats_.ramResidentBytes += bytes; break;
        case ResidencyTier::NVMe:  stats_.nvmeResidentBytes += bytes; break;
        default: break;
    }
}

void ElasticResidencyManager::markEvicted(const std::string& tensorName) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = tensors_.find(tensorName);
    if (it == tensors_.end()) return;
    auto& rec = it->second;
    if (rec.state == ResidencyState::Evicted) return;

    // Subtract from current tier
    switch (rec.tier) {
        case ResidencyTier::VRAM:  stats_.vramResidentBytes -= std::min(stats_.vramResidentBytes, rec.bytes); break;
        case ResidencyTier::RAM:   stats_.ramResidentBytes  -= std::min(stats_.ramResidentBytes,  rec.bytes); break;
        case ResidencyTier::NVMe:  stats_.nvmeResidentBytes -= std::min(stats_.nvmeResidentBytes, rec.bytes); break;
        default: break;
    }

    rec.state = ResidencyState::Evicted;
    rec.tier = ResidencyTier::Unknown;
    ++stats_.evictions;
    stats_.bytesEvicted += rec.bytes;
}

void ElasticResidencyManager::markPrefetched(const std::string& tensorName) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto& rec = tensors_[tensorName];
    rec.state = ResidencyState::Prefetching;
    ++stats_.prefetchHits;
}

void ElasticResidencyManager::markMiss(const std::string& tensorName, uint64_t bytes) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto& rec = tensors_[tensorName];
    rec.state = ResidencyState::Unknown;
    ++stats_.misses;
    stats_.bytesRequested += bytes; // account for the wasted request
}

void ElasticResidencyManager::setBudget(ResidencyTier tier, uint64_t maxBytes) {
    std::lock_guard<std::mutex> lock(mtx_);
    budget_[tier] = maxBytes;
}

bool ElasticResidencyManager::enforceBudget(ResidencyTier tier) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = budget_.find(tier);
    if (it == budget_.end()) return true; // no budget = always in budget

    const uint64_t used = tierBytes(tier);
    if (used <= it->second) return true;

    // Evict oldest Evictable/Resident tensors until budget satisfied
    std::vector<std::pair<uint64_t, std::string>> candidates;
    for (auto& kv : tensors_) {
        if (kv.second.tier == tier &&
            (kv.second.state == ResidencyState::Resident || kv.second.state == ResidencyState::Evictable)) {
            candidates.emplace_back(kv.second.lastAccessEpoch, kv.first);
        }
    }
    std::sort(candidates.begin(), candidates.end());

    uint64_t freed = 0;
    for (const auto& pair : candidates) {
        auto& rec = tensors_[pair.second];
        switch (rec.tier) {
            case ResidencyTier::VRAM:  stats_.vramResidentBytes -= std::min(stats_.vramResidentBytes, rec.bytes); break;
            case ResidencyTier::RAM:   stats_.ramResidentBytes  -= std::min(stats_.ramResidentBytes,  rec.bytes); break;
            case ResidencyTier::NVMe:  stats_.nvmeResidentBytes -= std::min(stats_.nvmeResidentBytes, rec.bytes); break;
            default: break;
        }
        rec.state = ResidencyState::Evicted;
        rec.tier = ResidencyTier::Unknown;
        freed += rec.bytes;
        ++stats_.evictions;
        stats_.bytesEvicted += rec.bytes;
        if (used - freed <= it->second) break;
    }
    return true;
}

ResidencyState ElasticResidencyManager::stateOf(const std::string& tensorName) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = tensors_.find(tensorName);
    return (it != tensors_.end()) ? it->second.state : ResidencyState::Unknown;
}

ResidencyTier ElasticResidencyManager::tierOf(const std::string& tensorName) const {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = tensors_.find(tensorName);
    return (it != tensors_.end()) ? it->second.tier : ResidencyTier::Unknown;
}

std::vector<ResidencyRequest> ElasticResidencyManager::buildPlanForLayer(uint32_t layer) const {
    std::lock_guard<std::mutex> lock(mtx_);
    std::vector<ResidencyRequest> out;
    auto it = layerTensorNames_.find(layer);
    if (it == layerTensorNames_.end()) return out;

    out.reserve(it->second.size());
    for (const auto& name : it->second) {
        auto tIt = tensors_.find(name);
        if (tIt == tensors_.end()) continue;
        const auto& rec = tIt->second;
        if (rec.state == ResidencyState::Resident || rec.state == ResidencyState::Prefetching)
            continue;
        ResidencyRequest req;
        req.layer = layer;
        req.tensorName = name;
        req.desiredTier = ResidencyTier::VRAM;
        req.bytes = rec.bytes;
        req.deadlineEpoch = currentEpoch_ + 1;
        req.priority = rec.priority;
        out.push_back(req);
    }
    return out;
}

uint64_t ElasticResidencyManager::tierBytes(ResidencyTier tier) const {
    uint64_t sum = 0;
    for (const auto& kv : tensors_) {
        if (kv.second.tier == tier && kv.second.state == ResidencyState::Resident)
            sum += kv.second.bytes;
    }
    return sum;
}

} // namespace Deep2
