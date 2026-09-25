#include "Deep2ExpertCacheBridge.h"
#include <algorithm>
#include <cstring>
#include <numeric>

namespace rawrxd::deep2 {

Deep2ExpertCacheBridge::Deep2ExpertCacheBridge(ExpertCacheConfig cfg,
                                               ExpertTransport transport,
                                               bool strictGpuOnly)
    : strictGpuOnly_(strictGpuOnly), cache_(cfg, transport) {}

Deep2ExpertCacheBridge::OwnedExpertBacking* Deep2ExpertCacheBridge::findBacking(ExpertKey key) {
    for (auto& b : backing_) if (b.key == key) return &b;
    return nullptr;
}

const Deep2ExpertCacheBridge::OwnedExpertBacking* Deep2ExpertCacheBridge::findBacking(ExpertKey key) const {
    for (const auto& b : backing_) if (b.key == key) return &b;
    return nullptr;
}

bool Deep2ExpertCacheBridge::importCatalog(const ExpertTensorCatalog& catalog) {
    bool allOk = true;
    const auto keys = catalog.keys();
    receipt_.catalogExperts = keys.size();
    backing_.reserve(backing_.size() + keys.size());

    for (const auto& key : keys) {
        const ExpertTensorGroup* g = catalog.find(key);
        if (!g || g->tensors.empty() || g->totalBytes == 0) {
            ++receipt_.registerFailures;
            allOk = false;
            continue;
        }

        OwnedExpertBacking b{};
        b.key = key;
        b.bytes.resize(g->totalBytes);
        b.offsets.reserve(g->tensors.size());
        size_t cursor = 0;
        for (const auto& t : g->tensors) {
            b.offsets.push_back(cursor);
            std::memcpy(b.bytes.data() + cursor, t.data, t.bytes);
            cursor += t.bytes;
        }

        backing_.push_back(std::move(b));
        auto& stored = backing_.back();
        ExpertLocation loc{};
        loc.hostPtr = stored.bytes.data();
        loc.bytes = stored.bytes.size();
        if (!cache_.registerExpert(key, loc)) {
            backing_.pop_back();
            ++receipt_.registerFailures;
            allOk = false;
            continue;
        }
        ++receipt_.registeredExperts;
    }
    return allOk;
}

CachedExpertBinding Deep2ExpertCacheBridge::acquire(ExpertKey key, uint64_t tokenIndex) {
    ExpertLease lease = cache_.acquire(key, tokenIndex);
    if (!lease) {
        ++receipt_.acquireFailures;
        if (strictGpuOnly_) ++receipt_.strictViolations;
        return {};
    }
    const OwnedExpertBacking* b = findBacking(key);
    if (!b) {
        ++receipt_.acquireFailures;
        if (strictGpuOnly_) ++receipt_.strictViolations;
        return {};
    }
    return CachedExpertBinding{key, lease.deviceHandle, lease.bytes, b->offsets, lease.hit};
}

void Deep2ExpertCacheBridge::noteRouterScores(uint32_t layer,
                                               const uint32_t* expertIds,
                                               const float* probabilities,
                                               size_t count,
                                               uint64_t tokenIndex) {
    if (!expertIds || !probabilities) return;
    for (size_t i = 0; i < count; ++i) {
        cache_.notePrediction(ExpertKey{layer, expertIds[i]}, probabilities[i], tokenIndex);
    }
}

size_t Deep2ExpertCacheBridge::prefetchTopK(uint32_t layer,
                                             const uint32_t* expertIds,
                                             const float* probabilities,
                                             size_t count,
                                             size_t topK,
                                             uint64_t tokenIndex) {
    if (!expertIds || count == 0 || topK == 0) return 0;
    std::vector<size_t> order(count);
    std::iota(order.begin(), order.end(), size_t{0});
    if (probabilities) {
        std::stable_sort(order.begin(), order.end(), [&](size_t a, size_t b) {
            return probabilities[a] > probabilities[b];
        });
    }
    const size_t n = std::min(topK, count);
    size_t ok = 0;
    for (size_t oi = 0; oi < n; ++oi) {
        ++receipt_.prefetchIssued;
        const size_t i = order[oi];
        if (cache_.prefetch(ExpertKey{layer, expertIds[i]}, tokenIndex)) ++ok;
        else ++receipt_.prefetchFailures;
    }
    return ok;
}

BridgeReceipt Deep2ExpertCacheBridge::receipt() const {
    BridgeReceipt r = receipt_;
    r.cache = cache_.stats();
    return r;
}

} // namespace rawrxd::deep2
