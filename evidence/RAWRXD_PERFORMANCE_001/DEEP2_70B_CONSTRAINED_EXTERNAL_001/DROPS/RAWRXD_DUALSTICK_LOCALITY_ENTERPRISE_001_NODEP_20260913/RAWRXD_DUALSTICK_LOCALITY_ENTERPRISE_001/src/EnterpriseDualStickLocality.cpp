#include "deep2/EnterpriseDualStickLocality.hpp"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <new>
#include <utility>

namespace Deep2 {
namespace enterprise_moe {

namespace {

bool AddOverflow(uint64_t a, uint64_t b, uint64_t& out) noexcept {
    if (b > std::numeric_limits<uint64_t>::max() - a) return true;
    out = a + b;
    return false;
}

uint64_t SafeAdd(uint64_t a, uint64_t b) noexcept {
    uint64_t o = 0;
    return AddOverflow(a, b, o) ? std::numeric_limits<uint64_t>::max() : o;
}

void MergeDelta(Stats& s, const BackendDelta& d, uint32_t stick) noexcept {
    s.h2dBytes = SafeAdd(s.h2dBytes, d.h2dBytes);
    s.d2hBytes = SafeAdd(s.d2hBytes, d.d2hBytes);
    if (stick < kMaxSticks)
        s.gpuWorkNs[stick] = SafeAdd(s.gpuWorkNs[stick], d.gpuWorkNs);
    s.joinWaitNs = SafeAdd(s.joinWaitNs, d.joinWaitNs);
    s.gpuSubmits = SafeAdd(s.gpuSubmits, d.gpuSubmits);
    s.gpuWaits = SafeAdd(s.gpuWaits, d.gpuWaits);
    s.gpuGemvCalls = SafeAdd(s.gpuGemvCalls, d.gpuGemvCalls);
    if (stick < kMaxSticks)
        s.gpuGemvCallsByStick[stick] = SafeAdd(s.gpuGemvCallsByStick[stick],
                                               d.gpuGemvCalls);
    s.hostGemvCalls = SafeAdd(s.hostGemvCalls, d.hostGemvCalls);
}

ExpertBundleView ViewOf(const LoadedExpertBundle& b) noexcept {
    ExpertBundleView v;
    v.gate = b.gate.bytes.empty() ? nullptr : b.gate.bytes.data();
    v.gateBytes = b.gate.bytes.size();
    v.gateType = b.gate.ggmlType;
    v.up = b.up.bytes.empty() ? nullptr : b.up.bytes.data();
    v.upBytes = b.up.bytes.size();
    v.upType = b.up.ggmlType;
    v.down = b.down.bytes.empty() ? nullptr : b.down.bytes.data();
    v.downBytes = b.down.bytes.size();
    v.downType = b.down.ggmlType;
    v.hiddenDim = b.hiddenDim;
    v.intermediateDim = b.intermediateDim;
    return v;
}

} // namespace

uint64_t LoadedExpertBundle::ByteSize() const noexcept {
    uint64_t n = 0;
    n = SafeAdd(n, static_cast<uint64_t>(gate.bytes.size()));
    n = SafeAdd(n, static_cast<uint64_t>(up.bytes.size()));
    n = SafeAdd(n, static_cast<uint64_t>(down.bytes.size()));
    return n;
}

bool LoadedExpertBundle::Valid() const noexcept {
    return !gate.bytes.empty() && !up.bytes.empty() && !down.bytes.empty() &&
           gate.ggmlType >= 0 && up.ggmlType >= 0 && down.ggmlType >= 0 &&
           hiddenDim > 0 && intermediateDim > 0 &&
           ByteSize() != std::numeric_limits<uint64_t>::max();
}

const char* Bool01(bool v) noexcept { return v ? "1" : "0"; }

uint64_t RouterFingerprint(const RoutedExpert* selected, uint32_t count) noexcept {
    /* FNV-1a over exact ID/weight/ordinal. preferredStick is scheduling, not quality. */
    uint64_t h = 1469598103934665603ull;
    const uint64_t prime = 1099511628211ull;
    if (!selected && count) return 0;
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t wbits = 0;
        static_assert(sizeof(wbits) == sizeof(selected[i].routerWeight), "float size");
        std::memcpy(&wbits, &selected[i].routerWeight, sizeof(wbits));
        const uint32_t vals[3] = {selected[i].expertId, wbits,
                                  selected[i].routerOrdinal};
        for (uint32_t v : vals) {
            for (unsigned b = 0; b < 4; ++b) {
                h ^= static_cast<uint8_t>((v >> (b * 8)) & 0xffu);
                h *= prime;
            }
        }
    }
    return h;
}

struct EnterpriseDualStickLocality::Impl {
    struct HostEntry {
        ExpertKey key{};
        LoadedExpertBundle bundle;
        uint64_t bytes = 0;
        uint64_t lastUse = 0;
    };

    struct ResidentEntry {
        ExpertKey key{};
        uint32_t stick = 0;
        uint64_t bytes = 0;
        uint64_t lastUse = 0;
        DeviceBundleHandle handle{};
        std::shared_ptr<HostEntry> host;
    };

    struct SeenState {
        bool everResident = false;
    };

    Config cfg{};
    LoaderOps loader{};
    BackendOps backend{};
    bool initialized = false;
    mutable std::mutex mu;
    uint64_t epoch = 1;
    Stats stats{};

    std::unordered_map<ExpertKey, std::shared_ptr<HostEntry>, ExpertKeyHash> host;
    std::unordered_map<ExpertKey, SeenState, ExpertKeyHash> seen;
    std::unordered_map<ExpertKey, ResidentEntry, ExpertKeyHash> resident[kMaxSticks];

    bool ValidateConfig(std::string& error) const {
        if (cfg.stickCount == 0 || cfg.stickCount > kMaxSticks) {
            error = "stickCount must be 1..2";
            return false;
        }
        if (cfg.maxTopK == 0 || cfg.maxTopK > kMaxTopK) {
            error = "maxTopK must be 1..16";
            return false;
        }
        for (uint32_t s = 0; s < cfg.stickCount; ++s) {
            if (!cfg.stickBudgetBytes[s]) {
                error = "stick budget must be non-zero";
                return false;
            }
        }
        if (!cfg.bundleAtomicity) {
            error = "enterprise locality requires Gate+Up+Down bundle atomicity";
            return false;
        }
        if (!loader.LoadBundle) {
            error = "LoadBundle callback required";
            return false;
        }
        if (!backend.DeviceCount || !backend.DualStickArmed ||
            !backend.EnsureBundle || !backend.SubmitExpert ||
            !backend.BeginLayer || !backend.EndLayerReduce) {
            error = "backend callbacks incomplete";
            return false;
        }
        return true;
    }

    bool EvictHostToFit(uint64_t incoming, const ExpertKey* protect,
                        std::string& error) {
        if (!cfg.hostStagingBudgetBytes) return true;
        if (incoming > cfg.hostStagingBudgetBytes) {
            error = "single expert bundle exceeds host staging budget";
            return false;
        }
        while (stats.hostStagingBytes > cfg.hostStagingBudgetBytes - incoming) {
            auto victim = host.end();
            uint64_t oldest = std::numeric_limits<uint64_t>::max();
            for (auto it = host.begin(); it != host.end(); ++it) {
                if (protect && it->first == *protect) continue;
                /* Cannot evict stable staging while any stick residency holds it. */
                bool pinned = false;
                for (uint32_t s = 0; s < cfg.stickCount; ++s) {
                    if (resident[s].find(it->first) != resident[s].end()) {
                        pinned = true;
                        break;
                    }
                }
                if (!pinned && it->second->lastUse < oldest) {
                    oldest = it->second->lastUse;
                    victim = it;
                }
            }
            if (victim == host.end()) {
                error = "host staging budget blocked by resident bundles";
                return false;
            }
            const uint64_t vb = victim->second->bytes;
            stats.hostStagingBytes = (vb <= stats.hostStagingBytes)
                                         ? stats.hostStagingBytes - vb
                                         : 0;
            ++stats.hostStageEvictions;
            host.erase(victim);
        }
        return true;
    }

    std::shared_ptr<HostEntry> GetHost(const ExpertKey& key, std::string& error) {
        auto it = host.find(key);
        if (it != host.end()) {
            it->second->lastUse = ++epoch;
            ++stats.hostStageHits;
            return it->second;
        }

        LoadedExpertBundle loaded;
        try {
            if (!loader.LoadBundle(loader.user, key, loaded, error)) return {};
        } catch (const std::bad_alloc&) {
            error = "LoadBundle allocation failure";
            return {};
        } catch (...) {
            error = "LoadBundle threw unexpected exception";
            return {};
        }
        if (!loaded.Valid()) {
            error = "LoadBundle returned invalid physical bundle";
            return {};
        }
        const uint64_t bytes = loaded.ByteSize();
        if (!EvictHostToFit(bytes, &key, error)) return {};

        std::shared_ptr<HostEntry> e;
        try {
            e = std::make_shared<HostEntry>();
            e->key = key;
            e->bundle = std::move(loaded);
            e->bytes = bytes;
            e->lastUse = ++epoch;
            host.emplace(key, e);
        } catch (const std::bad_alloc&) {
            error = "host staging allocation failure";
            return {};
        }
        stats.hostStagingBytes = SafeAdd(stats.hostStagingBytes, bytes);
        stats.hostStagingPeakBytes = std::max(stats.hostStagingPeakBytes,
                                               stats.hostStagingBytes);
        ++stats.hostStageLoads;
        return e;
    }

    int FindResidentStick(const ExpertKey& key) const {
        for (uint32_t s = 0; s < cfg.stickCount; ++s) {
            if (resident[s].find(key) != resident[s].end()) return static_cast<int>(s);
        }
        return -1;
    }

    bool EvictStickToFit(uint32_t stick, uint64_t incoming,
                         const ExpertKey& protect, bool& thrashed,
                         std::string& error) {
        if (stick >= cfg.stickCount) {
            error = "stick out of range";
            return false;
        }
        const uint64_t budget = cfg.stickBudgetBytes[stick];
        if (incoming > budget) {
            thrashed = true;
            error = "expert bundle exceeds stick budget";
            return false;
        }
        while (stats.currentResidentBytes[stick] > budget - incoming) {
            auto victim = resident[stick].end();
            uint64_t oldest = std::numeric_limits<uint64_t>::max();
            for (auto it = resident[stick].begin(); it != resident[stick].end(); ++it) {
                if (it->first == protect) continue;
                if (it->second.lastUse < oldest) {
                    oldest = it->second.lastUse;
                    victim = it;
                }
            }
            if (victim == resident[stick].end()) {
                thrashed = true;
                error = "stick budget cannot evict enough space";
                return false;
            }
            if (backend.ReleaseBundle) {
                backend.ReleaseBundle(backend.user, stick, victim->first,
                                      victim->second.handle);
            }
            const uint64_t vb = victim->second.bytes;
            stats.currentResidentBytes[stick] =
                vb <= stats.currentResidentBytes[stick]
                    ? stats.currentResidentBytes[stick] - vb
                    : 0;
            ++stats.bundleEvictions;
            resident[stick].erase(victim);
        }
        return true;
    }

    ResidentEntry* Ensure(const ExpertKey& key, uint32_t preferredStick,
                          bool& cacheHit, bool& layerThrash,
                          std::string& error) {
        ++stats.bundleLookups;
        int existing = FindResidentStick(key);
        if (existing >= 0 && cfg.retainResidentStick) {
            auto& r = resident[existing].find(key)->second;
            r.lastUse = ++epoch;
            cacheHit = true;
            ++stats.bundleHits;
            ++stats.stickRetains;
            stats.hitBytes = SafeAdd(stats.hitBytes, r.bytes);
            return &r;
        }

        uint32_t stick = preferredStick;
        if (stick >= cfg.stickCount) stick = key.expert % cfg.stickCount;
        if (!cfg.respectPlacerStickForCold) {
            /* Conservative load-aware cold assignment. Router quality is untouched. */
            uint32_t best = 0;
            uint64_t bestBytes = stats.currentResidentBytes[0];
            for (uint32_t s = 1; s < cfg.stickCount; ++s) {
                if (stats.currentResidentBytes[s] < bestBytes) {
                    best = s;
                    bestBytes = stats.currentResidentBytes[s];
                }
            }
            stick = best;
        }

        auto h = GetHost(key, error);
        if (!h) {
            ++stats.acquireFail;
            return nullptr;
        }
        const uint64_t bytes = h->bytes;
        if (!EvictStickToFit(stick, bytes, key, layerThrash, error)) {
            ++stats.acquireFail;
            return nullptr;
        }

        DeviceBundleHandle handle{};
        BackendDelta d{};
        const ExpertBundleView view = ViewOf(h->bundle);
        if (!backend.EnsureBundle(backend.user, stick, key, view, handle, d, error)) {
            MergeDelta(stats, d, stick);
            if (handle.valid && backend.ReleaseBundle)
                backend.ReleaseBundle(backend.user, stick, key, handle);
            ++stats.acquireFail;
            return nullptr;
        }
        MergeDelta(stats, d, stick);
        if (!handle.valid) {
            if (backend.ReleaseBundle)
                backend.ReleaseBundle(backend.user, stick, key, handle);
            error = "EnsureBundle succeeded without a valid device handle";
            ++stats.acquireFail;
            return nullptr;
        }

        ResidentEntry r;
        r.key = key;
        r.stick = stick;
        r.bytes = bytes;
        r.lastUse = ++epoch;
        r.handle = handle;
        r.host = h;
        auto ins = resident[stick].emplace(key, std::move(r));
        if (!ins.second) {
            if (backend.ReleaseBundle)
                backend.ReleaseBundle(backend.user, stick, key, handle);
            error = "resident cache insertion collision";
            ++stats.acquireFail;
            return nullptr;
        }

        cacheHit = false;
        ++stats.bundleMisses;
        ++stats.acquireOk;
        ++stats.stickAssignments;
        stats.currentResidentBytes[stick] = SafeAdd(stats.currentResidentBytes[stick], bytes);
        stats.peakResidentBytes[stick] = std::max(stats.peakResidentBytes[stick],
                                                  stats.currentResidentBytes[stick]);

        SeenState& ss = seen[key];
        if (!ss.everResident) {
            stats.compulsoryMissBytes = SafeAdd(stats.compulsoryMissBytes, bytes);
            ss.everResident = true;
        } else {
            stats.reloadMissBytes = SafeAdd(stats.reloadMissBytes, bytes);
        }
        return &ins.first->second;
    }

    bool ValidateRequest(const LayerRequest& req, std::string& error) const {
        if (!initialized) {
            error = "locality engine not initialized";
            return false;
        }
        if (!req.selected || !req.selectedCount || req.selectedCount > cfg.maxTopK) {
            error = "invalid selected expert set";
            return false;
        }
        if (!req.hidden || !req.hiddenCount || !req.routedOut) {
            error = "hidden/output buffer invalid";
            return false;
        }
        if (req.hiddenCount > std::numeric_limits<uint32_t>::max()) {
            error = "hiddenCount exceeds backend dimension range";
            return false;
        }
        for (uint32_t i = 0; i < req.selectedCount; ++i) {
            if (!std::isfinite(req.selected[i].routerWeight)) {
                error = "non-finite router weight";
                return false;
            }
            for (uint32_t j = i + 1; j < req.selectedCount; ++j) {
                if (req.selected[i].expertId == req.selected[j].expertId) {
                    error = "duplicate routed expert ID";
                    return false;
                }
            }
        }
        return true;
    }
};

EnterpriseDualStickLocality::EnterpriseDualStickLocality()
    : impl_(new Impl()) {}
EnterpriseDualStickLocality::~EnterpriseDualStickLocality() {
    if (impl_) ClearCaches();
}

bool EnterpriseDualStickLocality::Initialize(const Config& cfg,
                                              const LoaderOps& loader,
                                              const BackendOps& backend,
                                              std::string& error) {
    std::lock_guard<std::mutex> g(impl_->mu);
    if (impl_->initialized) {
        error = "locality engine already initialized";
        return false;
    }
    impl_->cfg = cfg;
    impl_->loader = loader;
    impl_->backend = backend;
    if (!impl_->ValidateConfig(error)) return false;
    impl_->initialized = true;
    return true;
}

void EnterpriseDualStickLocality::BeginToken() {
    std::lock_guard<std::mutex> g(impl_->mu);
    if (impl_->initialized) ++impl_->stats.tokensObserved;
}

bool EnterpriseDualStickLocality::ExecuteLayer(const LayerRequest& req,
                                                std::string& error) {
    std::lock_guard<std::mutex> g(impl_->mu);
    if (!impl_->ValidateRequest(req, error)) return false;

    const uint64_t before = RouterFingerprint(req.selected, req.selectedCount);
    impl_->stats.routerHashBefore = before;
    impl_->stats.expertsSelected =
        SafeAdd(impl_->stats.expertsSelected, req.selectedCount);
    ++impl_->stats.moeLayerCalls;

    struct Work {
        const RoutedExpert* routed = nullptr;
        Impl::ResidentEntry* resident = nullptr;
    };
    std::array<Work, kMaxTopK> work{};
    uint32_t wc = 0;
    bool layerThrash = false;

    /* Ensure all experts first. Never truncate top-k on budget pressure. */
    for (uint32_t i = 0; i < req.selectedCount; ++i) {
        ExpertKey key{req.layer, req.selected[i].expertId};
        bool hit = false;
        Impl::ResidentEntry* r =
            impl_->Ensure(key, req.selected[i].preferredStick, hit,
                          layerThrash, error);
        if (!r) {
            ++impl_->stats.topkDropFaults;
            ++impl_->stats.layerFailures;
            if (layerThrash) ++impl_->stats.thrashLayers;
            return false; /* fail request; never silently execute fewer experts */
        }
        work[wc++] = Work{&req.selected[i], r};
    }
    if (layerThrash) ++impl_->stats.thrashLayers;

    /* Group by stick while retaining immutable router IDs/weights. */
    std::stable_sort(work.begin(), work.begin() + wc,
                     [](const Work& a, const Work& b) {
                         if (a.resident->stick != b.resident->stick)
                             return a.resident->stick < b.resident->stick;
                         return a.routed->routerOrdinal < b.routed->routerOrdinal;
                     });

    if (!impl_->backend.BeginLayer(impl_->backend.user, req.layer,
                                   static_cast<uint32_t>(req.hiddenCount), error)) {
        ++impl_->stats.layerFailures;
        if (impl_->backend.AbortLayer)
            impl_->backend.AbortLayer(impl_->backend.user, req.layer);
        return false;
    }

    for (uint32_t i = 0; i < wc; ++i) {
        Work& w = work[i];
        Impl::ResidentEntry& r = *w.resident;
        const ExpertBundleView view = ViewOf(r.host->bundle);
        BackendDelta d{};
        if (!impl_->backend.SubmitExpert(impl_->backend.user, r.stick, r.key,
                                         view, r.handle, req.hidden,
                                         req.hiddenCount,
                                         w.routed->routerWeight, d, error)) {
            MergeDelta(impl_->stats, d, r.stick);
            ++impl_->stats.layerFailures;
            if (impl_->backend.AbortLayer)
                impl_->backend.AbortLayer(impl_->backend.user, req.layer);
            return false;
        }
        MergeDelta(impl_->stats, d, r.stick);
        ++impl_->stats.expertsExecuted;
        if (r.stick < kMaxSticks) ++impl_->stats.stickExperts[r.stick];
        r.lastUse = ++impl_->epoch;
    }

    BackendDelta join{};
    if (!impl_->backend.EndLayerReduce(impl_->backend.user, req.layer,
                                       req.routedOut, req.hiddenCount,
                                       join, error)) {
        MergeDelta(impl_->stats, join, 0);
        ++impl_->stats.layerFailures;
        if (impl_->backend.AbortLayer)
            impl_->backend.AbortLayer(impl_->backend.user, req.layer);
        return false;
    }
    MergeDelta(impl_->stats, join, 0);

    const uint64_t after = RouterFingerprint(req.selected, req.selectedCount);
    impl_->stats.routerHashAfter = after;
    if (before != after) {
        ++impl_->stats.routerMutationFaults;
        ++impl_->stats.layerFailures;
        error = "router IDs/weights mutated by execution path";
        return false;
    }
    if (impl_->stats.expertsExecuted > impl_->stats.expertsSelected) {
        ++impl_->stats.layerFailures;
        error = "expert execution counter exceeded selection counter";
        return false;
    }
    return true;
}

bool EnterpriseDualStickLocality::Prefetch(uint32_t layer,
                                            const RoutedExpert* selected,
                                            uint32_t selectedCount,
                                            std::string& error) {
    std::lock_guard<std::mutex> g(impl_->mu);
    if (!impl_->initialized || !selected || !selectedCount ||
        selectedCount > impl_->cfg.maxTopK) {
        error = "invalid prefetch request";
        return false;
    }
    bool layerThrash = false;
    for (uint32_t i = 0; i < selectedCount; ++i) {
        ExpertKey key{layer, selected[i].expertId};
        bool hit = false;
        if (!impl_->Ensure(key, selected[i].preferredStick, hit,
                           layerThrash, error)) {
            if (layerThrash) ++impl_->stats.thrashLayers;
            return false;
        }
    }
    if (layerThrash) ++impl_->stats.thrashLayers;
    return true;
}

Stats EnterpriseDualStickLocality::Snapshot() const {
    std::lock_guard<std::mutex> g(impl_->mu);
    return impl_->stats;
}

AuthorityResult EnterpriseDualStickLocality::Evaluate(
    const PerformanceObservation& perf) const {
    std::lock_guard<std::mutex> g(impl_->mu);
    const Stats& s = impl_->stats;
    AuthorityResult r;
    r.structuralParity =
        s.expertsSelected > 0 && s.expertsSelected == s.expertsExecuted &&
        s.acquireFail == 0 && s.routerMutationFaults == 0 &&
        s.topkDropFaults == 0 && s.layerFailures == 0;

    const uint32_t dc = impl_->backend.DeviceCount
                            ? impl_->backend.DeviceCount(impl_->backend.user)
                            : 0;
    const bool armed = impl_->backend.DualStickArmed
                           ? impl_->backend.DualStickArmed(impl_->backend.user)
                           : false;
    r.bothSticksExecuted = armed && dc >= 2 && s.stickExperts[0] > 0 &&
                           s.stickExperts[1] > 0 &&
                           s.gpuGemvCallsByStick[0] > 0 &&
                           s.gpuGemvCallsByStick[1] > 0 &&
                           s.hostGemvCalls == 0;

    r.reloadMetricMeasured = s.tokensObserved > 0 && s.bundleLookups > 0;
    const uint64_t miss = SafeAdd(s.compulsoryMissBytes, s.reloadMissBytes);
    r.missMetricImproved =
        r.reloadMetricMeasured && impl_->cfg.baselineMissBytesPerToken > 0 &&
        (miss / s.tokensObserved) < impl_->cfg.baselineMissBytesPerToken;

    r.matchedWallAuthority =
        perf.matchedHostAvailable && perf.generatedTokens > 0 && perf.wallNs > 0 &&
        perf.layerDepth > 0 && perf.layerDepth == perf.matchedHostLayerDepth &&
        perf.generatedTokens == perf.matchedHostGeneratedTokens &&
        perf.matchedHostWallNs > 0;
    if (r.matchedWallAuthority) {
        const long double ds = static_cast<long double>(perf.wallNs) /
                               static_cast<long double>(perf.generatedTokens);
        const long double host =
            static_cast<long double>(perf.matchedHostWallNs) /
            static_cast<long double>(perf.matchedHostGeneratedTokens);
        r.wallImproved = ds < host;
    }

    r.productBackendAttested = impl_->cfg.productBackendAttested;
    r.performanceAuthority = r.productBackendAttested && r.structuralParity &&
                             r.bothSticksExecuted && r.reloadMetricMeasured &&
                             r.missMetricImproved && r.matchedWallAuthority &&
                             r.wallImproved;
    r.promote = false;

    if (!r.structuralParity)
        r.disposition = "HOLD_STRUCTURAL_PARITY";
    else if (!r.bothSticksExecuted)
        r.disposition = "HOLD_BOTH_STICKS_GPU_EXEC";
    else if (!r.missMetricImproved)
        r.disposition = "HOLD_LOCALITY_NOT_IMPROVED";
    else if (!r.matchedWallAuthority)
        r.disposition = "HOLD_WALL_AUTHORITY_UNMATCHED";
    else if (!r.wallImproved)
        r.disposition = "HOLD_MATCHED_WALL_REGRESSION";
    else if (!r.productBackendAttested)
        r.disposition = "HOLD_PRODUCT_BACKEND_UNATTESTED";
    else if (r.performanceAuthority)
        r.disposition = "PERFORMANCE_GATE_PASS_PROMOTE_STILL_0";
    else
        r.disposition = "HOLD_UNCLASSIFIED";
    return r;
}

bool EnterpriseDualStickLocality::WriteReceipt(
    FILE* f, const PerformanceObservation& perf, const char* gateName) const {
    if (!f) return false;
    std::lock_guard<std::mutex> g(impl_->mu);
    const Stats& s = impl_->stats;
    /* Evaluate inline to avoid recursive mutex lock. */
    AuthorityResult a;
    a.structuralParity =
        s.expertsSelected > 0 && s.expertsSelected == s.expertsExecuted &&
        s.acquireFail == 0 && s.routerMutationFaults == 0 &&
        s.topkDropFaults == 0 && s.layerFailures == 0;
    const uint32_t dc = impl_->backend.DeviceCount
                            ? impl_->backend.DeviceCount(impl_->backend.user)
                            : 0;
    const bool armed = impl_->backend.DualStickArmed
                           ? impl_->backend.DualStickArmed(impl_->backend.user)
                           : false;
    a.bothSticksExecuted = armed && dc >= 2 && s.stickExperts[0] > 0 &&
                           s.stickExperts[1] > 0 &&
                           s.gpuGemvCallsByStick[0] > 0 &&
                           s.gpuGemvCallsByStick[1] > 0 &&
                           s.hostGemvCalls == 0;
    a.reloadMetricMeasured = s.tokensObserved > 0 && s.bundleLookups > 0;
    const uint64_t totalMiss = SafeAdd(s.compulsoryMissBytes, s.reloadMissBytes);
    const uint64_t missPerToken = s.tokensObserved ? totalMiss / s.tokensObserved : 0;
    const uint64_t reloadPerToken = s.tokensObserved ? s.reloadMissBytes / s.tokensObserved : 0;
    a.missMetricImproved = a.reloadMetricMeasured &&
                           impl_->cfg.baselineMissBytesPerToken > 0 &&
                           missPerToken < impl_->cfg.baselineMissBytesPerToken;
    a.matchedWallAuthority =
        perf.matchedHostAvailable && perf.generatedTokens > 0 && perf.wallNs > 0 &&
        perf.layerDepth > 0 && perf.layerDepth == perf.matchedHostLayerDepth &&
        perf.generatedTokens == perf.matchedHostGeneratedTokens &&
        perf.matchedHostWallNs > 0;
    if (a.matchedWallAuthority) {
        const long double dsw = static_cast<long double>(perf.wallNs) /
                                static_cast<long double>(perf.generatedTokens);
        const long double hw = static_cast<long double>(perf.matchedHostWallNs) /
                               static_cast<long double>(perf.matchedHostGeneratedTokens);
        a.wallImproved = dsw < hw;
    }
    a.productBackendAttested = impl_->cfg.productBackendAttested;
    a.performanceAuthority = a.productBackendAttested && a.structuralParity &&
                             a.bothSticksExecuted && a.reloadMetricMeasured &&
                             a.missMetricImproved && a.matchedWallAuthority &&
                             a.wallImproved;
    a.promote = false;
    if (!a.structuralParity)
        a.disposition = "HOLD_STRUCTURAL_PARITY";
    else if (!a.bothSticksExecuted)
        a.disposition = "HOLD_BOTH_STICKS_GPU_EXEC";
    else if (!a.missMetricImproved)
        a.disposition = "HOLD_LOCALITY_NOT_IMPROVED";
    else if (!a.matchedWallAuthority)
        a.disposition = "HOLD_WALL_AUTHORITY_UNMATCHED";
    else if (!a.wallImproved)
        a.disposition = "HOLD_MATCHED_WALL_REGRESSION";
    else if (!a.productBackendAttested)
        a.disposition = "HOLD_PRODUCT_BACKEND_UNATTESTED";
    else if (a.performanceAuthority)
        a.disposition = "PERFORMANCE_GATE_PASS_PROMOTE_STILL_0";
    else
        a.disposition = "HOLD_UNCLASSIFIED";

    const uint64_t hitPerToken = s.tokensObserved ? s.hitBytes / s.tokensObserved : 0;
    const uint64_t dsNsPerToken = perf.generatedTokens ? perf.wallNs / perf.generatedTokens : 0;
    const uint64_t hostNsPerToken =
        perf.matchedHostGeneratedTokens
            ? perf.matchedHostWallNs / perf.matchedHostGeneratedTokens
            : 0;

    std::fprintf(f,
        "GATE=%s\n"
        "SOURCE_DROP=RAWRXD_DUALSTICK_LOCALITY_ENTERPRISE_001\n"
        "NO_THIRD_PARTY_DEPS=1\n"
        "ROUTER_IDS_WEIGHTS_IMMUTABLE=1\n"
        "TOPK_DROP_ON_THRASH=0\n"
        "TOKENS_OBSERVED=%llu\n"
        "MOE_LAYER_CALLS=%llu\n"
        "LAYER_FAILURES=%llu\n"
        "EXPERTS_SELECTED=%llu\n"
        "EXPERTS_EXECUTED=%llu\n"
        "EXPERT_PARITY=%s\n"
        "ACQUIRE_OK=%llu\n"
        "ACQUIRE_FAIL=%llu\n"
        "BUNDLE_LOOKUPS=%llu\n"
        "BUNDLE_HITS=%llu\n"
        "BUNDLE_MISSES=%llu\n"
        "BUNDLE_EVICTIONS=%llu\n"
        "HOST_STAGE_LOADS=%llu\n"
        "HOST_STAGE_HITS=%llu\n"
        "COMPULSORY_MISS_BYTES=%llu\n"
        "RELOAD_MISS_BYTES=%llu\n"
        "HIT_BYTES=%llu\n"
        "EXPERT_MISS_BYTES_PER_TOKEN=%llu\n"
        "RELOAD_MISS_BYTES_PER_TOKEN=%llu\n"
        "HIT_BYTES_PER_TOKEN=%llu\n"
        "STICK0_EXPERTS=%llu\n"
        "STICK1_EXPERTS=%llu\n"
        "H2D_BYTES=%llu\n"
        "D2H_BYTES=%llu\n"
        "GPU_SUBMITS=%llu\n"
        "GPU_WAITS=%llu\n"
        "GPU_GEMV_CALLS=%llu\n"
        "GPU0_GEMV_CALLS=%llu\n"
        "GPU1_GEMV_CALLS=%llu\n"
        "HOST_GEMV_CALLS=%llu\n"
        "JOIN_WAIT_NS=%llu\n"
        "ROUTER_MUTATION_FAULTS=%llu\n"
        "TOPK_DROP_FAULTS=%llu\n"
        "THRASH_LAYERS=%llu\n"
        "DUALSTICK_ARMED=%s\n"
        "DEVICE_COUNT=%u\n"
        "STRUCTURAL_PARITY=%s\n"
        "BOTH_STICKS_EXECUTED=%s\n"
        "PRODUCT_BACKEND_ATTESTED=%s\n"
        "BASELINE_MISS_BYTES_PER_TOKEN=%llu\n"
        "MISS_METRIC_IMPROVED=%s\n"
        "LAYER_DEPTH=%u\n"
        "GENERATED_TOKENS=%llu\n"
        "DS_WALL_NS_PER_TOKEN=%llu\n"
        "MATCHED_HOST_AVAILABLE=%s\n"
        "MATCHED_HOST_LAYER_DEPTH=%u\n"
        "MATCHED_HOST_GENERATED_TOKENS=%llu\n"
        "MATCHED_HOST_WALL_NS_PER_TOKEN=%llu\n"
        "MATCHED_WALL_AUTHORITY=%s\n"
        "WALL_IMPROVED=%s\n"
        "TPS_PERFORMANCE_AUTHORITY=%s\n"
        "TARGET_35_50_TPS=UNMINTED\n"
        "PROMOTE=0\n"
        "DISPOSITION=%s\n",
        gateName ? gateName : "DEEP2_DUALSTICK_LOCALITY_ENTERPRISE_001",
        (unsigned long long)s.tokensObserved,
        (unsigned long long)s.moeLayerCalls,
        (unsigned long long)s.layerFailures,
        (unsigned long long)s.expertsSelected,
        (unsigned long long)s.expertsExecuted,
        Bool01(a.structuralParity),
        (unsigned long long)s.acquireOk,
        (unsigned long long)s.acquireFail,
        (unsigned long long)s.bundleLookups,
        (unsigned long long)s.bundleHits,
        (unsigned long long)s.bundleMisses,
        (unsigned long long)s.bundleEvictions,
        (unsigned long long)s.hostStageLoads,
        (unsigned long long)s.hostStageHits,
        (unsigned long long)s.compulsoryMissBytes,
        (unsigned long long)s.reloadMissBytes,
        (unsigned long long)s.hitBytes,
        (unsigned long long)missPerToken,
        (unsigned long long)reloadPerToken,
        (unsigned long long)hitPerToken,
        (unsigned long long)s.stickExperts[0],
        (unsigned long long)s.stickExperts[1],
        (unsigned long long)s.h2dBytes,
        (unsigned long long)s.d2hBytes,
        (unsigned long long)s.gpuSubmits,
        (unsigned long long)s.gpuWaits,
        (unsigned long long)s.gpuGemvCalls,
        (unsigned long long)s.gpuGemvCallsByStick[0],
        (unsigned long long)s.gpuGemvCallsByStick[1],
        (unsigned long long)s.hostGemvCalls,
        (unsigned long long)s.joinWaitNs,
        (unsigned long long)s.routerMutationFaults,
        (unsigned long long)s.topkDropFaults,
        (unsigned long long)s.thrashLayers,
        Bool01(armed), dc,
        Bool01(a.structuralParity), Bool01(a.bothSticksExecuted),
        Bool01(a.productBackendAttested),
        (unsigned long long)impl_->cfg.baselineMissBytesPerToken,
        Bool01(a.missMetricImproved), perf.layerDepth,
        (unsigned long long)perf.generatedTokens,
        (unsigned long long)dsNsPerToken,
        Bool01(perf.matchedHostAvailable),
        perf.matchedHostLayerDepth,
        (unsigned long long)perf.matchedHostGeneratedTokens,
        (unsigned long long)hostNsPerToken,
        Bool01(a.matchedWallAuthority), Bool01(a.wallImproved),
        Bool01(a.performanceAuthority), a.disposition.c_str());
    return std::ferror(f) == 0;
}

void EnterpriseDualStickLocality::ResetRuntimeStats() {
    std::lock_guard<std::mutex> g(impl_->mu);
    const uint64_t rb0 = impl_->stats.currentResidentBytes[0];
    const uint64_t rb1 = impl_->stats.currentResidentBytes[1];
    const uint64_t hs = impl_->stats.hostStagingBytes;
    impl_->stats = Stats{};
    impl_->stats.currentResidentBytes[0] = rb0;
    impl_->stats.currentResidentBytes[1] = rb1;
    impl_->stats.hostStagingBytes = hs;
    impl_->stats.peakResidentBytes[0] = rb0;
    impl_->stats.peakResidentBytes[1] = rb1;
    impl_->stats.hostStagingPeakBytes = hs;
}

void EnterpriseDualStickLocality::ClearCaches() {
    std::lock_guard<std::mutex> g(impl_->mu);
    for (uint32_t s = 0; s < impl_->cfg.stickCount; ++s) {
        if (impl_->backend.ReleaseBundle) {
            for (auto& kv : impl_->resident[s]) {
                impl_->backend.ReleaseBundle(impl_->backend.user, s, kv.first,
                                             kv.second.handle);
            }
        }
        impl_->resident[s].clear();
    }
    impl_->host.clear();
    impl_->seen.clear();
    impl_->stats.currentResidentBytes[0] = 0;
    impl_->stats.currentResidentBytes[1] = 0;
    impl_->stats.hostStagingBytes = 0;
}

} // namespace enterprise_moe
} // namespace Deep2
