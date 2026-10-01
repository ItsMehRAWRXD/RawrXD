// RAWRXD_DEEP2_EXPERT_CONTROL_PLANE_CERT_001
//
// Runtime certification for the adopted Deep2 expert control plane:
//   Deep2PredictiveRouter   -> ExpertCache::notePrediction
//   ExpertScheduler         -> Deep2MultiGpuExpertCache placement
//   Deep2MultiGpuExpertCache-> per-device ExpertCache
//
// Every field printed below is measured from live calls made in this process.
// There are no hardcoded verdict inputs: VERDICT is derived only from measured
// counters.
//
// Scope limits, stated so this receipt cannot be read as a stronger claim:
//   * This cert does NOT claim Deep2Engine drives this plane. It certifies that
//     the previously-dead translation units compile, link into InferenceEngine,
//     and execute when fed real routing traffic.
//   * It does NOT claim semantic parity for any model.
//   * It does NOT measure GPU or NVMe bandwidth. The transport is a host-memory
//     simulator so that placement decisions are attributable to the scheduler
//     rather than to device timing noise.

#include "Deep2PredictiveRouter.hpp"
#include "expert_cache/Deep2MultiGpuExpertCache.h"
#include "expert_cache/ExpertCache.h"
#include "expert_cache/ExpertScheduler.h"
#include "expert_cache/ExpertTensorCatalog.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <numeric>
#include <random>
#include <string>
#include <vector>

namespace {

struct TransportSim {
    uint64_t allocCalls = 0;
    uint64_t freeCalls = 0;
    uint64_t uploadCalls = 0;
    uint64_t uploadBytes = 0;
};

void* simAlloc(void* user, size_t bytes, uint32_t) {
    auto* s = static_cast<TransportSim*>(user);
    ++s->allocCalls;
    return std::malloc(bytes ? bytes : 1);
}

void simFree(void* user, void* handle, uint32_t) {
    auto* s = static_cast<TransportSim*>(user);
    ++s->freeCalls;
    std::free(handle);
}

bool simUpload(void* user, void* handle, const void* src, size_t bytes, uint32_t) {
    auto* s = static_cast<TransportSim*>(user);
    ++s->uploadCalls;
    s->uploadBytes += bytes;
    if (!handle || !src || bytes == 0) return false;
    std::memcpy(handle, src, bytes);
    return true;
}

uint64_t simNow(void*) {
    static uint64_t t = 0;
    return ++t;
}

} // namespace

int main() {
    // ---- Routing traffic with a deliberately skewed heat profile. A uniform
    // distribution would make every placement decision a tie and would not
    // exercise the scheduler at all.
    constexpr uint32_t kLayers = 8;
    constexpr uint32_t kExperts = 16;
    constexpr uint32_t kTopK = 2;
    // Each expert is registered as a gate/up/down triple, so the cache's byte
// accounting sees 3 x this, not this. Measured: TRANSPORT_UPLOAD_BYTES divided
// by TRANSPORT_UPLOAD_CALLS must equal kExpertBytes * 3 at runtime.
constexpr size_t kTensorBytes = 16 * 1024;
constexpr size_t kExpertBytes = kTensorBytes * 3;
// Per-device budget must exceed the live working set. The router sends 4 hot
// experts to each of 8 layers = 32 live experts = 1.5 MiB. Two devices at
// 2 MiB each hold 42 experts, so the hot set fits with headroom and placement
// differences become observable instead of every acquire failing on capacity.
constexpr uint32_t kDeviceBudgetBytes = 2 * 1024 * 1024;
    constexpr uint32_t kTokens = 400;

    std::mt19937 rng(0x5EED1234u);
    std::vector<float> logits(kExperts);

    TransportSim sim0{};
    TransportSim sim1{};

    rawrxd::deep2::MultiGpuExpertDeviceConfig dev0{};
    dev0.cache.budgetBytes = kDeviceBudgetBytes;
    dev0.cache.deviceOrdinal = 0;
    dev0.cache.prefetchDepth = 2;
    dev0.transport.user = &sim0;
    dev0.transport.allocDevice = &simAlloc;
    dev0.transport.freeDevice = &simFree;
    dev0.transport.upload = &simUpload;
    dev0.transport.nowMicros = &simNow;

    rawrxd::deep2::MultiGpuExpertDeviceConfig dev1 = dev0;
    dev1.cache.deviceOrdinal = 1;
    dev1.transport.user = &sim1;

    rawrxd::deep2::MultiGpuExpertRuntimeConfig rtCfg{};
    rtCfg.enabled = true;
    rtCfg.strictGpuOnly = true;
    rtCfg.evictSourceAfterMigration = false; // keep both owners resident so a
                                            // migration is observable instead
                                            // of being masked by an eviction.
    rtCfg.prefetchDepth = 3;

    rawrxd::deep2::Deep2MultiGpuExpertCache multi({dev0, dev1}, rtCfg);

    // ---- Catalog built through the real GGUF-name parser, so
    // ExpertTensorCatalog::addTensor and parseExpertKey are exercised rather
    // than bypassed by direct insertion.
    rawrxd::deep2::ExpertTensorCatalog catalog;
    std::vector<std::vector<uint8_t>> payload(kLayers * kExperts);
    uint64_t catalogBytes = 0;
    uint32_t tensorsAdded = 0;
    for (uint32_t L = 0; L < kLayers; ++L) {
        for (uint32_t e = 0; e < kExperts; ++e) {
            auto& buf = payload[L * kExperts + e];
            buf.resize(kExpertBytes);
            for (size_t i = 0; i < buf.size(); ++i)
                buf[i] = static_cast<uint8_t>((L * 31u + e * 17u + i * 7u) & 0xFFu);

            // Three tensors per expert, mirroring the gate/up/down triple the
            // engine registers at Deep2Engine.cpp:2168.
            for (const char* suffix : {"gate", "up", "down"}) {
                rawrxd::deep2::ExpertTensorView v{};
                v.name = "blk." + std::to_string(L) + ".experts." +
                         std::to_string(e) + "." + suffix + ".weight";
                // Distinct byte ranges inside the same buffer so a
                // mis-sliced concatenation is detectable, not just a size match.
                const size_t off =
                    (std::strcmp(suffix, "gate") == 0)   ? 0
                    : (std::strcmp(suffix, "up") == 0)    ? kTensorBytes
                                                           : kTensorBytes * 2;
                v.data = buf.data() + off;
                v.bytes = kTensorBytes;
                if (catalog.addTensor(v)) ++tensorsAdded;
            }
            catalogBytes += buf.size();
        }
    }
    const bool imported = multi.importCatalog(catalog);

    Deep2::Roofline::PredictiveRouter predictor;

    uint64_t acquires = 0, acquireHits = 0, acquireFailures = 0;
    uint64_t prefetchRequests = 0, prefetchAccepted = 0;
    uint64_t predictedKeys = 0, predictionMatches = 0, predictionRounds = 0;
    uint64_t payloadChecks = 0;

    for (uint32_t token = 0; token < kTokens; ++token) {
        const uint32_t L = token % kLayers;

        // Skewed router logits: experts 0-3 hot, 4-7 warm, 8-15 cold.
        for (uint32_t e = 0; e < kExperts; ++e)
            logits[e] = (e < 4)   ? (3.0f - 0.10f * static_cast<float>(e))
                       : (e < 8) ? (1.0f - 0.10f * static_cast<float>(e))
                                 : (-3.0f - 0.10f * static_cast<float>(e));
        // Deterministic jitter so the top-k is not a constant tie.
        for (uint32_t e = 0; e < kExperts; ++e)
            logits[e] += 0.01f * static_cast<float>(rng() % 100u);

        std::vector<std::pair<float, uint32_t>> ranked;
        ranked.reserve(kExperts);
        for (uint32_t e = 0; e < kExperts; ++e)
            ranked.push_back({logits[e], e});
        std::partial_sort(ranked.begin(), ranked.begin() + kTopK, ranked.end(),
                          [](const auto& a, const auto& b) {
                              return a.first > b.first;
                          });

        // PREDICT BEFORE OBSERVE. Predicting after observing the current route
        // would trivially match and would measure nothing.
        const auto predicted = predictor.predict(L, kTopK);
        ++predictionRounds;
        predictedKeys += predicted.size();

        std::vector<uint32_t> observed;
        float weightSum = 0.0f;
        for (uint32_t k = 0; k < kTopK; ++k) weightSum += ranked[k].first;

        std::vector<rawrxd::deep2::RoutedExpertHint> hints;
        hints.reserve(kTopK);
        for (uint32_t k = 0; k < kTopK; ++k) {
            const uint32_t e = ranked[k].second;
            observed.push_back(e);
            hints.push_back({{L, e},
                             weightSum > 0.0f ? ranked[k].first / weightSum : 0.0f});
        }

        predictor.observe(L, observed);

        // Measure the prediction against the route actually used this token.
        for (const uint32_t p : predicted)
            for (const uint32_t t : observed)
                if (p == t) { ++predictionMatches; break; }

        // Non-binding predictive prefetch.
        prefetchRequests += hints.size();
        prefetchAccepted += multi.prefetchPredicted(hints.data(), hints.size(), token);

        // Demand path on the same router output.
        for (const auto& h : hints) {
            const auto binding = multi.acquire(h, token);
            if (!binding) { ++acquireFailures; continue; }
            ++acquires;
            if (binding.cacheHit) ++acquireHits;

            const auto& src = payload[L * kExperts + h.key.expert];
            ++payloadChecks;
            if (std::memcmp(binding.deviceHandle, src.data(), src.size()) != 0) {
                std::fprintf(stderr, "PAYLOAD_MISMATCH layer=%u expert=%u device=%u\n",
                             L, h.key.expert, binding.deviceOrdinal);
                std::printf("PAYLOAD_INTEGRITY=FAIL\nVERDICT=FAIL\n");
                return 2;
            }
            multi.release(binding);
        }
    }

    const auto receipt = multi.receipt();
    uint64_t dev0Bytes = 0, dev1Bytes = 0, dev0Owned = 0, dev1Owned = 0;
    uint64_t dev0Hits = 0, dev1Hits = 0;
    uint64_t dev0Budget = 0, dev1Budget = 0, dev0Inflight = 0, dev1Inflight = 0;
    for (const auto& d : receipt.devices) {
        if (d.deviceOrdinal == 0) {
            dev0Bytes = d.cache.residentBytes;
            dev0Owned = d.ownedExperts;
            dev0Hits = d.cache.hits;
            dev0Budget = d.cache.budgetBytes;
            dev0Inflight = d.cache.inflightBytes;
        } else {
            dev1Bytes = d.cache.residentBytes;
            dev1Owned = d.ownedExperts;
            dev1Hits = d.cache.hits;
            dev1Budget = d.cache.budgetBytes;
            dev1Inflight = d.cache.inflightBytes;
        }
    }

    const auto catStats = catalog.stats();

    // ---- Scheduler feasibility probe. Printed unconditionally so a capacity
    // rejection downstream can be attributed to the scheduler state rather than
    // guessed at.
    {
        std::vector<rawrxd::ExpertDeviceState> states;
        for (uint32_t ord = 0; ord < 2; ++ord) {
            rawrxd::ExpertDeviceState ds{};
            ds.deviceId = ord;
            ds.budgetBytes = kDeviceBudgetBytes;
            ds.residentBytes = (ord == 0) ? dev0Bytes : dev1Bytes;
            ds.inflightBytes = 0;
            ds.available = true;
            states.push_back(ds);
        }
        rawrxd::ExpertScheduler sched{};
        rawrxd::ExpertPlacementRequest probe{};
        probe.layer = 0;
        probe.expert = 0;
        probe.bytes = kExpertBytes;
        probe.routerProbability = 1.0f;
        probe.currentDevice = -1;
        const auto d = sched.choose(probe, states);
        std::printf("PROBE_DEVICE_BUDGET_BYTES=%u\n", kDeviceBudgetBytes);
        std::printf("PROBE_EXPERT_BYTES=%u\n", (unsigned)kExpertBytes);
        std::printf("PROBE_CHOSEN_DEVICE=%d\n", d.device);
        std::printf("PROBE_SCORE_FINITE=%d\n", std::isfinite(d.score) ? 1 : 0);
    }

    std::printf("CATALOG_TENSORS_ADDED=%u\n", tensorsAdded);
    std::printf("CATALOG_EXPERTS_DISCOVERED=%llu\n",
                (unsigned long long)catStats.expertsDiscovered);
    std::printf("CATALOG_EXPERT_TENSORS_MATCHED=%llu\n",
                (unsigned long long)catStats.expertTensorsMatched);
    std::printf("CATALOG_REJECTED_NAME=%llu\n",
                (unsigned long long)catStats.rejectedName);
    std::printf("CATALOG_IMPORT_OK=%d\n", imported ? 1 : 0);
    std::printf("CATALOG_EXPERTS=%llu\n", (unsigned long long)receipt.catalogExperts);
    std::printf("CATALOG_BYTES=%llu\n", (unsigned long long)catalogBytes);
    std::printf("REGISTERED_EXPERTS=%llu\n", (unsigned long long)receipt.registeredExperts);
    std::printf("REGISTER_FAILURES=%llu\n", (unsigned long long)receipt.registerFailures);
    std::printf("TOKENS=%u\n", kTokens);
    std::printf("ACQUIRES=%llu\n", (unsigned long long)acquires);
    std::printf("ACQUIRE_HITS=%llu\n", (unsigned long long)acquireHits);
    std::printf("ACQUIRE_FAILURES=%llu\n", (unsigned long long)acquireFailures);
    std::printf("SCHEDULER_DECISIONS=%llu\n", (unsigned long long)receipt.schedulerDecisions);
    std::printf("SCHEDULER_MIGRATIONS=%llu\n", (unsigned long long)receipt.migrations);
    std::printf("SCHEDULER_REJECTED_NO_CAPACITY=%llu\n",
                (unsigned long long)receipt.rejectedNoCapacity);
    std::printf("PREFETCH_REQUESTS=%llu\n", (unsigned long long)prefetchRequests);
    std::printf("PREFETCH_ACCEPTED=%llu\n", (unsigned long long)prefetchAccepted);
    std::printf("PREDICTIVE_ROUTER_ROUNDS=%llu\n", (unsigned long long)predictionRounds);
    std::printf("PREDICTIVE_ROUTER_KEYS=%llu\n", (unsigned long long)predictedKeys);
    std::printf("PREDICTIVE_ROUTER_MATCHES=%llu\n", (unsigned long long)predictionMatches);
    std::printf("PAYLOAD_INTEGRITY_CHECKS=%llu\n", (unsigned long long)payloadChecks);
    std::printf("TRANSPORT_ALLOC_CALLS=%llu\n",
                (unsigned long long)(sim0.allocCalls + sim1.allocCalls));
    std::printf("TRANSPORT_UPLOAD_CALLS=%llu\n",
                (unsigned long long)(sim0.uploadCalls + sim1.uploadCalls));
    std::printf("TRANSPORT_UPLOAD_BYTES=%llu\n",
                (unsigned long long)(sim0.uploadBytes + sim1.uploadBytes));
    std::printf("TRANSPORT_FREE_CALLS=%llu\n",
                (unsigned long long)(sim0.freeCalls + sim1.freeCalls));
    std::printf("DEVICE0_RESIDENT_BYTES=%llu\n", (unsigned long long)dev0Bytes);
    std::printf("DEVICE1_RESIDENT_BYTES=%llu\n", (unsigned long long)dev1Bytes);
    std::printf("DEVICE0_BUDGET_BYTES=%llu\n", (unsigned long long)dev0Budget);
    std::printf("DEVICE1_BUDGET_BYTES=%llu\n", (unsigned long long)dev1Budget);
    std::printf("DEVICE0_INFLIGHT_BYTES=%llu\n", (unsigned long long)dev0Inflight);
    std::printf("DEVICE1_INFLIGHT_BYTES=%llu\n", (unsigned long long)dev1Inflight);
    std::printf("DEVICE0_OWNED_EXPERTS=%llu\n", (unsigned long long)dev0Owned);
    std::printf("DEVICE1_OWNED_EXPERTS=%llu\n", (unsigned long long)dev1Owned);
    std::printf("DEVICE0_CACHE_HITS=%llu\n", (unsigned long long)dev0Hits);
    std::printf("DEVICE1_CACHE_HITS=%llu\n", (unsigned long long)dev1Hits);
    std::printf("STRICT_GPU_VIOLATIONS=%llu\n",
                (unsigned long long)receipt.strictGpuViolations);
    std::printf("CPU_EXPERT_COMPUTE=%llu\n", (unsigned long long)receipt.cpuExpertCompute);

    // ---- Derived checks. Each is a comparison between two measured values.
    const bool catalogClean = catStats.rejectedName == 0 &&
                              catStats.expertTensorsMatched == tensorsAdded &&
                              catStats.expertsDiscovered == kLayers * kExperts;
    const bool cleanImport = imported && receipt.registerFailures == 0 &&
                             receipt.registeredExperts == receipt.catalogExperts &&
                             receipt.catalogExperts == kLayers * kExperts;
    const bool bothDevicesUsed = dev0Bytes > 0 && dev1Bytes > 0 &&
                                 dev0Hits > 0 && dev1Hits > 0;
    const bool residencyBounded = dev0Bytes <= kDeviceBudgetBytes &&
                                  dev1Bytes <= kDeviceBudgetBytes;
    const bool schedulerRan = receipt.schedulerDecisions > 0;
    const bool cacheServed = acquires > 0 && acquireHits > 0;
    const bool uploadsHappened = (sim0.uploadCalls + sim1.uploadCalls) > 0 &&
                                 (sim0.uploadBytes + sim1.uploadBytes) > 0;
    const bool predictorRan = predictionRounds > 0 && predictedKeys > 0;
    const bool predictorUseful = predictionMatches > 0;
    const bool prefetchPathRan = prefetchRequests > 0;
    const bool noCpuFallback = receipt.cpuExpertCompute == 0;
    const bool noStrictViolations = receipt.strictGpuViolations == 0;
    const bool payloadIntact = payloadChecks == acquires;

    // Byte accounting must equal the concatenated gate/up/down triple, not one
    // tensor. A cache that silently under-counts would over-admit experts.
    const uint64_t uploadCallsTotal = sim0.uploadCalls + sim1.uploadCalls;
    const uint64_t bytesPerUpload = uploadCallsTotal
        ? (sim0.uploadBytes + sim1.uploadBytes) / uploadCallsTotal : 0;
    std::printf("BYTES_PER_UPLOAD=%llu\n", (unsigned long long)bytesPerUpload);
    std::printf("EXPECTED_BYTES_PER_UPLOAD=%llu\n", (unsigned long long)kExpertBytes);
    const bool byteAccountingExact = (uploadCallsTotal > 0) &&
                                     (bytesPerUpload == kExpertBytes);

    std::printf("CATALOG_PARSER_CLEAN=%d\n", catalogClean ? 1 : 0);
    std::printf("MULTIGPU_BOTH_DEVICES_SERVED=%d\n", bothDevicesUsed ? 1 : 0);
    std::printf("RESIDENCY_BUDGET_RESPECTED=%d\n", residencyBounded ? 1 : 0);
    std::printf("EXPERT_SCHEDULER_RUNTIME_HITS=%d\n", schedulerRan ? 1 : 0);
    std::printf("EXPERT_CACHE_RUNTIME_HITS=%d\n", cacheServed ? 1 : 0);
    std::printf("EXPERT_CACHE_UPLOAD_EVIDENCE=%d\n", uploadsHappened ? 1 : 0);
    std::printf("PREDICTIVE_ROUTER_RUNTIME_HITS=%d\n", predictorRan ? 1 : 0);
    std::printf("PREDICTION_MATCHED_REAL_ROUTE=%d\n", predictorUseful ? 1 : 0);
    std::printf("PREDICTIVE_PREFETCH_RAN=%d\n", prefetchPathRan ? 1 : 0);
    std::printf("PAYLOAD_INTEGRITY=%d\n", payloadIntact ? 1 : 0);
    std::printf("EXPERT_BYTE_ACCOUNTING_EXACT=%d\n", byteAccountingExact ? 1 : 0);
    std::printf("NO_CPU_EXPERT_FALLBACK=%d\n", noCpuFallback ? 1 : 0);
    std::printf("NO_STRICT_GPU_VIOLATION=%d\n", noStrictViolations ? 1 : 0);

    const bool pass = catalogClean && cleanImport && bothDevicesUsed &&
                      residencyBounded && schedulerRan && cacheServed &&
                      uploadsHappened && predictorRan && predictorUseful &&
                      prefetchPathRan && payloadIntact && byteAccountingExact &&
                      noCpuFallback && noStrictViolations;

    std::printf("VERDICT=%s\n", pass ? "PASS" : "FAIL");
    return pass ? 0 : 1;
}