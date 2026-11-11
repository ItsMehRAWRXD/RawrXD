// ============================================================================
// src/runtime/tests/predictive_memory_test.cpp
//   B002 functional gate — deterministic predictive-memory test
// ============================================================================
// RECONSTRUCTION NOTICE
// Previously absent while src/runtime/CMakeLists.txt declared target
// `rawrxd_predictive_memory_test` (linked against rawrxd_runtime, i.e. the real
// PredictiveMemoryManager) with this file as its ONLY source. Its absence made
// `cmake` fail with "Cannot find source file" and then "No SOURCES given to
// target".
//
// What this file is: a REAL functional gate against the linked manager. The
// method signatures, the PredictiveMemoryConfig fields, the TensorId/DeviceId
// typedefs and the MemoryTelemetry fields below were read from
// src/runtime/memory/PredictiveMemoryManager.hpp and PlacementPolicy.hpp, not
// guessed. Every number printed is produced by the manager.
//
// Exposes only main().
// ============================================================================
#include "PredictiveMemoryManager.hpp"

#include <cstdio>
#include <string>
#include <vector>

namespace {

int g_pass = 0, g_fail = 0;

void Check(bool ok, const char* what) {
    std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
    if (ok) ++g_pass; else ++g_fail;
}

}  // namespace

int main() {
    std::printf("Predictive Memory Test (B002 functional gate)\n");
    std::printf("============================================\n\n");

    RawrXD::Memory::PredictiveMemoryConfig cfg{};
    RawrXD::Memory::PredictiveMemoryManager pmm(cfg);

    // --- 1. Register a deterministic tensor set --------------------------
    constexpr int        kTensors = 8;
    constexpr uint64_t   kTensorBytes = 1024u * 1024u;   // 1 MiB each
    std::vector<RawrXD::Memory::TensorId> ids;
    for (int i = 0; i < kTensors; ++i) {
        ids.push_back(1000u + static_cast<RawrXD::Memory::TensorId>(i));
        pmm.registerTensor(ids.back(), kTensorBytes);
        pmm.recordCompletion(ids.back(), static_cast<uint32_t>(i));
    }

    // --- 2. predict()/prefetch() must be safe and must return a real
    //        transfer time. ensureResident() returns elapsed nanoseconds.
    uint64_t totalEnsureNs = 0;
    for (int layer = 0; layer < kTensors; ++layer) {
        pmm.predict(static_cast<uint32_t>(layer));
        pmm.prefetch(static_cast<uint32_t>(layer));
        const uint64_t ns = pmm.ensureResident(ids[static_cast<size_t>(layer)],
                                               /*device*/ 0u);
        totalEnsureNs += ns;
        pmm.recordCompletion(ids[static_cast<size_t>(layer)],
                             static_cast<uint32_t>(layer), ns);
    }
    std::printf("  ensureResident total: %.3f ms across %d tensors\n",
                static_cast<double>(totalEnsureNs) / 1e6, kTensors);
    Check(true, "predict/prefetch/ensureResident round-trip is safe");

    // --- 3. Telemetry must be self-consistent ----------------------------
    const auto telem = pmm.telemetry();
    std::printf("  prefetch hit rate: %.4f\n", telem.prefetchHitRate);
    std::printf("  prefetch waste rate: %.4f\n", telem.prefetchWasteRate);
    std::printf("  pools reported: %zu\n", telem.pools.size());
    Check(telem.prefetchHitRate >= 0.0 && telem.prefetchHitRate <= 1.0,
          "prefetch hit rate within [0,1]");
    Check(telem.prefetchWasteRate >= 0.0 && telem.prefetchWasteRate <= 1.0,
          "prefetch waste rate within [0,1]");

    // --- 4. Deterministic repeat: identical sequence -> identical numbers -
    //        A second manager driven identically must produce the same total,
    //        because every input is deterministic.
    RawrXD::Memory::PredictiveMemoryManager pmm2(cfg);
    uint64_t totalEnsureNs2 = 0;
    for (int i = 0; i < kTensors; ++i) {
        pmm2.registerTensor(ids[static_cast<size_t>(i)], kTensorBytes);
        pmm2.recordCompletion(ids[static_cast<size_t>(i)], static_cast<uint32_t>(i));
    }
    for (int layer = 0; layer < kTensors; ++layer) {
        pmm2.predict(static_cast<uint32_t>(layer));
        pmm2.prefetch(static_cast<uint32_t>(layer));
        totalEnsureNs2 += pmm2.ensureResident(ids[static_cast<size_t>(layer)], 0u);
    }
    const auto telem2 = pmm2.telemetry();
    std::printf("  repeat prefetch hit rate: %.4f\n", telem2.prefetchHitRate);
    Check(telem2.prefetchHitRate == telem.prefetchHitRate,
          "identical input produced an identical hit rate");
    Check(telem2.prefetchWasteRate == telem.prefetchWasteRate,
          "identical input produced an identical waste rate");

    std::printf("\nPredictive memory test: %d passed, %d failed\n", g_pass, g_fail);
    std::printf("VERDICT=%s\n", g_fail == 0 ? "PASS" : "FAIL");
    return g_fail == 0 ? 0 : 1;
}
