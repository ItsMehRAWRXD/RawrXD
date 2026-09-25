#include "ExpertCache.h"
#include <algorithm>
#include <limits>

namespace rawrxd::deep2 {

static float clamp01(float v) {
    if (v < 0.0f) return 0.0f;
    if (v > 1.0f) return 1.0f;
    return v;
}

ExpertCache::ExpertCache(ExpertCacheConfig cfg, ExpertTransport transport)
    : cfg_(cfg), transport_(transport) {
    if (cfg_.emaAlpha <= 0.0f || cfg_.emaAlpha > 1.0f) cfg_.emaAlpha = 0.10f;
    stats_.budgetBytes = cfg_.budgetBytes;
}

ExpertCache::~ExpertCache() { clear(); }

bool ExpertCache::registerExpert(ExpertKey key, ExpertLocation loc) {
    if (!loc.hostPtr || loc.bytes == 0) return false;
    std::lock_guard<std::mutex> lock(mu_);
    auto& e = entries_[key];
    if (e.resident || e.loading) return false;
    e.loc = loc;
    return true;
}

float ExpertCache::scoreLocked(const Entry& e, uint64_t nowToken) const {
    if (cfg_.policy == ExpertCachePolicy::Lru) return static_cast<float>(e.lastUsedToken);
    const uint64_t age = (nowToken >= e.lastUsedToken) ? (nowToken - e.lastUsedToken) : 0;
    const float recency = 1.0f / (1.0f + static_cast<float>(age));
    return (e.emaFrequency * 0.60f) + (e.predictedValue * 0.30f) + (recency * 0.10f);
}

bool ExpertCache::finishAsyncLocked(Entry& e, bool wait) {
    if (!e.loading) return e.resident;
    if (!transport_.pollUpload || !transport_.waitUpload || e.uploadTicket == 0) return false;

    const uint64_t waitStart = wait && transport_.nowMicros ? transport_.nowMicros(transport_.user) : 0;
    bool ready = false;
    if (!wait) {
        ready = transport_.pollUpload(transport_.user, e.uploadTicket, cfg_.deviceOrdinal);
        if (!ready) return false;
        ++stats_.asyncPollReady;
    } else {
        ++stats_.asyncWaits;
        ready = transport_.waitUpload(transport_.user, e.uploadTicket, cfg_.deviceOrdinal);
    }
    const uint64_t t1 = transport_.nowMicros ? transport_.nowMicros(transport_.user) : 0;
    if (t1 >= e.uploadStartMicros) stats_.transferMicros += (t1 - e.uploadStartMicros);
    if (wait && t1 >= waitStart) stats_.stallMicros += (t1 - waitStart);

    const size_t bytes = e.loc.bytes;
    if (stats_.inflightBytes >= bytes) stats_.inflightBytes -= bytes;
    else stats_.inflightBytes = 0;

    if (!ready) {
        ++stats_.asyncFailures;
        ++stats_.uploadFailures;
        if (e.deviceHandle && transport_.freeDevice)
            transport_.freeDevice(transport_.user, e.deviceHandle, cfg_.deviceOrdinal);
        e.deviceHandle = nullptr;
        e.loading = false;
        e.uploadTicket = 0;
        e.uploadStartMicros = 0;
        return false;
    }

    stats_.residentBytes += bytes;
    e.loading = false;
    e.resident = true;
    e.uploadTicket = 0;
    e.uploadStartMicros = 0;
    return true;
}
bool ExpertCache::ensureSpaceLocked(size_t bytesNeeded, uint64_t tokenIndex, const ExpertKey* protectedKey) {
    if (bytesNeeded > cfg_.budgetBytes) return false;
    while (stats_.residentBytes + stats_.inflightBytes + bytesNeeded > cfg_.budgetBytes) {
        auto victimIt = entries_.end();
        float victimScore = std::numeric_limits<float>::max();
        for (auto it = entries_.begin(); it != entries_.end(); ++it) {
            if (!it->second.resident && !it->second.loading) continue;
            if (protectedKey && it->first == *protectedKey) continue;
            const float s = scoreLocked(it->second, tokenIndex);
            if (s < victimScore) { victimScore = s; victimIt = it; }
        }
        if (victimIt == entries_.end()) return false;
        if (!evictLocked(victimIt->first, victimIt->second)) return false;
    }
    return true;
}

bool ExpertCache::loadLocked(const ExpertKey& key, Entry& e, uint64_t tokenIndex, bool isPrefetch, bool* outHit) {
    if (outHit) *outHit = false;

    if (e.loading) {
        if (isPrefetch) {
            if (finishAsyncLocked(e, false)) {
                if (outHit) *outHit = true;
                ++stats_.prefetchHits;
            }
            return true; // still a successful prefetch if transfer remains in-flight
        }
        // Demand path first polls. A completed prefetch must not become an artificial
        // fence wait merely because the entry is still marked loading.
        if (!finishAsyncLocked(e, false) && e.loading) {
            if (!finishAsyncLocked(e, true)) return false;
        }
        if (outHit) *outHit = true;
        e.lastUsedToken = tokenIndex;
        return true;
    }

    if (e.resident) {
        if (outHit) *outHit = true;
        e.lastUsedToken = tokenIndex;
        if (isPrefetch) ++stats_.prefetchHits;
        return true;
    }

    if (!transport_.allocDevice || !transport_.freeDevice) return false;
    if (!ensureSpaceLocked(e.loc.bytes, tokenIndex, &key)) return false;

    const uint64_t t0 = transport_.nowMicros ? transport_.nowMicros(transport_.user) : 0;
    void* h = transport_.allocDevice(transport_.user, e.loc.bytes, cfg_.deviceOrdinal);
    if (!h) { ++stats_.uploadFailures; return false; }

    const bool hasAsync = transport_.submitUpload && transport_.pollUpload && transport_.waitUpload;
    if (hasAsync && isPrefetch) {
        const uint64_t ticket = transport_.submitUpload(transport_.user, h, e.loc.hostPtr, e.loc.bytes, cfg_.deviceOrdinal);
        if (!ticket) {
            transport_.freeDevice(transport_.user, h, cfg_.deviceOrdinal);
            ++stats_.uploadFailures;
            ++stats_.asyncFailures;
            return false;
        }
        e.deviceHandle = h;
        e.loading = true;
        e.uploadTicket = ticket;
        e.uploadStartMicros = t0;
        e.lastUsedToken = tokenIndex;
        stats_.inflightBytes += e.loc.bytes; // reserve budget while in flight
        stats_.bytesUploaded += e.loc.bytes;
        ++stats_.asyncSubmits;
        return true;
    }

    // Demand path may use async transport too, but it waits before exposing the handle.
    if (hasAsync) {
        const uint64_t ticket = transport_.submitUpload(transport_.user, h, e.loc.hostPtr, e.loc.bytes, cfg_.deviceOrdinal);
        if (!ticket) {
            transport_.freeDevice(transport_.user, h, cfg_.deviceOrdinal);
            ++stats_.uploadFailures; ++stats_.asyncFailures;
            return false;
        }
        e.deviceHandle = h;
        e.loading = true;
        e.uploadTicket = ticket;
        e.uploadStartMicros = t0;
        e.lastUsedToken = tokenIndex;
        stats_.inflightBytes += e.loc.bytes;
        stats_.bytesUploaded += e.loc.bytes;
        ++stats_.asyncSubmits;
        if (!finishAsyncLocked(e, true)) return false;
        return true;
    }

    if (!transport_.upload || !transport_.upload(transport_.user, h, e.loc.hostPtr, e.loc.bytes, cfg_.deviceOrdinal)) {
        transport_.freeDevice(transport_.user, h, cfg_.deviceOrdinal);
        ++stats_.uploadFailures;
        return false;
    }
    const uint64_t t1 = transport_.nowMicros ? transport_.nowMicros(transport_.user) : 0;
    e.deviceHandle = h;
    e.resident = true;
    e.lastUsedToken = tokenIndex;
    stats_.residentBytes += e.loc.bytes;
    stats_.bytesUploaded += e.loc.bytes;
    if (t1 >= t0) { stats_.transferMicros += (t1 - t0); stats_.stallMicros += (t1 - t0); }
    return true;
}

ExpertLease ExpertCache::acquire(ExpertKey key, uint64_t tokenIndex) {
    std::lock_guard<std::mutex> lock(mu_);
    ++stats_.requests;
    auto it = entries_.find(key);
    if (it == entries_.end()) { ++stats_.misses; return {}; }
    Entry& e = it->second;
    const bool wasResident = e.resident || e.loading;
    bool hit = false;
    if (!loadLocked(key, e, tokenIndex, false, &hit)) { ++stats_.misses; return {}; }
    if (wasResident) ++stats_.hits; else ++stats_.misses;
    ++e.hits;
    e.emaFrequency = (1.0f - cfg_.emaAlpha) * e.emaFrequency + cfg_.emaAlpha;
    e.predictedValue *= 0.90f;
    return ExpertLease{key, e.deviceHandle, e.loc.bytes, hit};
}

bool ExpertCache::prefetch(ExpertKey key, uint64_t tokenIndex) {
    std::lock_guard<std::mutex> lock(mu_);
    ++stats_.prefetchRequests;
    auto it = entries_.find(key);
    if (it == entries_.end()) return false;
    bool hit = false;
    return loadLocked(key, it->second, tokenIndex, true, &hit);
}

void ExpertCache::notePrediction(ExpertKey key, float probability, uint64_t tokenIndex) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = entries_.find(key);
    if (it == entries_.end()) return;
    Entry& e = it->second;
    e.predictedValue = std::max(e.predictedValue * 0.90f, clamp01(probability));
    e.lastUsedToken = std::max(e.lastUsedToken, tokenIndex);
}

size_t ExpertCache::warmStart(const std::vector<ExpertKey>& keys, uint64_t tokenIndex) {
    size_t loaded = 0;
    for (const auto& k : keys) if (prefetch(k, tokenIndex)) ++loaded;
    return loaded;
}

bool ExpertCache::evictLocked(const ExpertKey&, Entry& e) {
    if (!e.resident && !e.loading) return true;
    if (!transport_.freeDevice) return false;
    if (e.loading && !finishAsyncLocked(e, true)) return false;
    transport_.freeDevice(transport_.user, e.deviceHandle, cfg_.deviceOrdinal);
    e.deviceHandle = nullptr;
    e.resident = false;
    e.loading = false;
    e.uploadTicket = 0;
    if (stats_.residentBytes >= e.loc.bytes) stats_.residentBytes -= e.loc.bytes;
    else stats_.residentBytes = 0;
    ++stats_.evictions;
    return true;
}

bool ExpertCache::evict(ExpertKey key) {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = entries_.find(key);
    if (it == entries_.end()) return false;
    return evictLocked(key, it->second);
}

void ExpertCache::clear() {
    std::lock_guard<std::mutex> lock(mu_);
    for (auto& kv : entries_) {
        auto& e = kv.second;
        if ((e.resident || e.loading) && transport_.freeDevice) {
            if (e.loading) finishAsyncLocked(e, true);
            if (e.deviceHandle) transport_.freeDevice(transport_.user, e.deviceHandle, cfg_.deviceOrdinal);
            e.deviceHandle = nullptr; e.resident = false; e.loading = false; e.uploadTicket = 0;
        }
    }
    stats_.residentBytes = 0;
    stats_.inflightBytes = 0;
}

ExpertCacheStats ExpertCache::stats() const { std::lock_guard<std::mutex> lock(mu_); return stats_; }

bool ExpertCache::isResident(ExpertKey key) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = entries_.find(key);
    return it != entries_.end() && it->second.resident;
}

void* ExpertCache::residentHandle(ExpertKey key) const {
    std::lock_guard<std::mutex> lock(mu_);
    auto it = entries_.find(key);
    return (it != entries_.end() && it->second.resident) ? it->second.deviceHandle : nullptr;
}

} // namespace rawrxd::deep2
