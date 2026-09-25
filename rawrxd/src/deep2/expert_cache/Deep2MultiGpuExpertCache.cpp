#include "Deep2MultiGpuExpertCache.h"
#include <algorithm>
#include <cstring>
#include <numeric>

namespace rawrxd::deep2 {

Deep2MultiGpuExpertCache::Deep2MultiGpuExpertCache(
    std::vector<MultiGpuExpertDeviceConfig> devices,
    MultiGpuExpertRuntimeConfig cfg) : cfg_(cfg) {
    devices_.reserve(devices.size());
    for (auto& d : devices) {
        DeviceRuntime rt{};
        rt.ordinal = d.cache.deviceOrdinal;
        rt.available = d.available;
        rt.cache = std::make_unique<ExpertCache>(d.cache, d.transport);
        devices_.push_back(std::move(rt));
    }
}

Deep2MultiGpuExpertCache::DeviceRuntime*
Deep2MultiGpuExpertCache::findDevice(uint32_t ordinal) {
    for (auto& d : devices_) if (d.ordinal == ordinal) return &d;
    return nullptr;
}

const Deep2MultiGpuExpertCache::DeviceRuntime*
Deep2MultiGpuExpertCache::findDevice(uint32_t ordinal) const {
    for (const auto& d : devices_) if (d.ordinal == ordinal) return &d;
    return nullptr;
}

const Deep2MultiGpuExpertCache::OwnedExpertBacking*
Deep2MultiGpuExpertCache::findBacking(ExpertKey key) const {
    const auto it = backingIndex_.find(key);
    if (it == backingIndex_.end() || it->second >= backing_.size()) return nullptr;
    return &backing_[it->second];
}

bool Deep2MultiGpuExpertCache::importCatalog(const ExpertTensorCatalog& catalog) {
    if (!backing_.empty()) return false; // host pointers are stable after one import
    const auto keys = catalog.keys();
    counters_.catalogExperts = keys.size();
    backing_.reserve(keys.size());
    backingIndex_.reserve(keys.size());

    bool allOk = true;
    for (const auto& key : keys) {
        const ExpertTensorGroup* g = catalog.find(key);
        if (!g || g->tensors.empty() || g->totalBytes == 0) {
            ++counters_.registerFailures;
            allOk = false;
            continue;
        }

        OwnedExpertBacking b{};
        b.key = key;
        b.bytes.resize(g->totalBytes);
        b.tensorOffsets.reserve(g->tensors.size());
        size_t cursor = 0;
        for (const auto& t : g->tensors) {
            if (!t.data || t.bytes == 0 || cursor > b.bytes.size() - t.bytes) {
                ++counters_.registerFailures;
                allOk = false;
                b.bytes.clear();
                break;
            }
            b.tensorOffsets.push_back(cursor);
            std::memcpy(b.bytes.data() + cursor, t.data, t.bytes);
            cursor += t.bytes;
        }
        if (b.bytes.empty()) continue;

        const size_t idx = backing_.size();
        backing_.push_back(std::move(b));
        backingIndex_.emplace(key, idx);
        const auto& stored = backing_.back();
        ExpertLocation loc{stored.bytes.data(), stored.bytes.size(), 0};

        bool everyDevice = !devices_.empty();
        for (auto& d : devices_) {
            if (!d.cache->registerExpert(key, loc)) everyDevice = false;
        }
        if (!everyDevice) {
            ++counters_.registerFailures;
            allOk = false;
        } else {
            ++counters_.registeredExperts;
        }
    }
    return allOk;
}

void Deep2MultiGpuExpertCache::updateDevicePressure(uint32_t deviceOrdinal,
                                                     uint64_t recentComputeUs,
                                                     uint64_t recentTransferUs,
                                                     bool available) {
    if (auto* d = findDevice(deviceOrdinal)) {
        d->recentComputeUs = recentComputeUs;
        d->recentTransferUs = recentTransferUs;
        d->available = available;
    }
}

int32_t Deep2MultiGpuExpertCache::readyOwner(ExpertKey key) const {
    const auto it = readyOwners_.find(key);
    if (it == readyOwners_.end()) return -1;
    const auto* d = findDevice(it->second);
    if (!d || !d->cache->isResident(key)) return -1;
    return static_cast<int32_t>(it->second);
}

int32_t Deep2MultiGpuExpertCache::placementHint(ExpertKey key) const {
    const auto p = plannedOwners_.find(key);
    if (p != plannedOwners_.end()) return static_cast<int32_t>(p->second);
    return readyOwner(key);
}

std::vector<rawrxd::ExpertDeviceState> Deep2MultiGpuExpertCache::schedulerStates() const {
    std::vector<rawrxd::ExpertDeviceState> out;
    out.reserve(devices_.size());
    for (const auto& d : devices_) {
        const auto s = d.cache->stats();
        rawrxd::ExpertDeviceState ds{};
        ds.deviceId = d.ordinal;
        ds.budgetBytes = s.budgetBytes;
        ds.residentBytes = s.residentBytes;
        ds.inflightBytes = s.inflightBytes;
        ds.recentComputeUs = d.recentComputeUs;
        ds.recentTransferUs = d.recentTransferUs;
        ds.available = d.available;
        out.push_back(ds);
    }
    return out;
}

rawrxd::ExpertPlacementDecision
Deep2MultiGpuExpertCache::chooseDevice(ExpertKey key, float probability) const {
    const auto* b = findBacking(key);
    if (!b) return {};
    rawrxd::ExpertPlacementRequest req{};
    req.layer = key.layer;
    req.expert = key.expert;
    req.bytes = b->bytes.size();
    req.routerProbability = probability;
    req.currentDevice = placementHint(key);
    return scheduler_.choose(req, schedulerStates());
}

size_t Deep2MultiGpuExpertCache::prefetchPredicted(const RoutedExpertHint* hints,
                                                    size_t count,
                                                    uint64_t tokenIndex) {
    if (!cfg_.enabled || !hints || count == 0 || cfg_.prefetchDepth == 0) return 0;
    std::vector<size_t> order(count);
    std::iota(order.begin(), order.end(), size_t{0});
    std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) {
        return hints[a].probability > hints[b].probability;
    });

    const size_t n = std::min<size_t>(cfg_.prefetchDepth, count);
    size_t ok = 0;
    for (size_t oi = 0; oi < n; ++oi) {
        const auto& h = hints[order[oi]];
        ++counters_.schedulerDecisions;
        const auto decision = chooseDevice(h.key, h.probability);
        if (decision.device < 0) {
            ++counters_.rejectedNoCapacity;
            continue;
        }
        auto* d = findDevice(static_cast<uint32_t>(decision.device));
        if (!d) { ++counters_.rejectedNoCapacity; continue; }
        d->cache->notePrediction(h.key, h.probability, tokenIndex);
        ++counters_.prefetchIssued;
        if (!d->cache->prefetch(h.key, tokenIndex)) {
            ++counters_.prefetchFailures;
            continue;
        }
        plannedOwners_[h.key] = d->ordinal;
        ++ok;
    }
    return ok;
}

MultiGpuExpertBinding Deep2MultiGpuExpertCache::acquire(RoutedExpertHint hint, uint64_t tokenIndex) {
    const auto* b = findBacking(hint.key);
    if (!b) {
        ++counters_.acquireFailures;
        if (cfg_.strictGpuOnly) ++counters_.strictGpuViolations;
        return {};
    }

    ++counters_.schedulerDecisions;
    const int32_t oldReadyOwner = readyOwner(hint.key);
    auto decision = chooseDevice(hint.key, hint.probability);
    if (decision.device < 0) {
        ++counters_.rejectedNoCapacity;
        ++counters_.acquireFailures;
        if (cfg_.strictGpuOnly) ++counters_.strictGpuViolations;
        return {};
    }

    auto* d = findDevice(static_cast<uint32_t>(decision.device));
    if (!d) {
        ++counters_.acquireFailures;
        if (cfg_.strictGpuOnly) ++counters_.strictGpuViolations;
        return {};
    }

    d->cache->notePrediction(hint.key, hint.probability, tokenIndex);
    ExpertLease lease = d->cache->acquire(hint.key, tokenIndex);
    if (!lease) {
        ++counters_.acquireFailures;
        if (cfg_.strictGpuOnly) ++counters_.strictGpuViolations;
        return {};
    }

    const bool migrated = oldReadyOwner >= 0 && oldReadyOwner != decision.device;
    if (migrated) {
        ++counters_.migrations;
        if (cfg_.evictSourceAfterMigration) {
            if (auto* old = findDevice(static_cast<uint32_t>(oldReadyOwner))) old->cache->evict(hint.key);
        }
    }
    readyOwners_[hint.key] = d->ordinal;
    plannedOwners_.erase(hint.key);

    return MultiGpuExpertBinding{
        hint.key, lease.deviceHandle, lease.bytes, b->tensorOffsets,
        d->ordinal, lease.hit, migrated
    };
}

void Deep2MultiGpuExpertCache::release(const MultiGpuExpertBinding& binding) {
    if (!binding) return;
    if (cfg_.enabled) return;
    if (auto* d = findDevice(binding.deviceOrdinal)) {
        if (d->cache->evict(binding.key)) ++counters_.releaseEvictions;
    }
    readyOwners_.erase(binding.key);
    plannedOwners_.erase(binding.key);
}

size_t Deep2MultiGpuExpertCache::warmStart(const std::vector<RoutedExpertHint>& hotExperts,
                                           uint64_t tokenIndex) {
    if (!cfg_.enabled) return 0;
    size_t loaded = 0;
    for (const auto& h : hotExperts) {
        if (prefetchPredicted(&h, 1, tokenIndex)) ++loaded;
    }
    return loaded;
}

MultiGpuExpertReceipt Deep2MultiGpuExpertCache::receipt() const {
    MultiGpuExpertReceipt r = counters_;
    r.devices.clear();
    for (const auto& d : devices_) {
        MultiGpuDeviceReceipt dr{};
        dr.deviceOrdinal = d.ordinal;
        dr.recentComputeUs = d.recentComputeUs;
        dr.recentTransferUs = d.recentTransferUs;
        dr.cache = d.cache->stats();
        for (const auto& kv : readyOwners_) {
            if (kv.second == d.ordinal && d.cache->isResident(kv.first)) ++dr.ownedExperts;
        }
        r.devices.push_back(dr);
    }
    return r;
}

} // namespace rawrxd::deep2
