// Demonstration / certification harness.
// Shows how 99% effective work avoidance can be reached for repeated deterministic
// segments WITHOUT claiming arbitrary novel tokens can skip 99% of model math.

#include "beaconism_99.hpp"
#include <cstdio>
#include <cstring>
#include <cmath>

using namespace rawrxd::beaconism;

static void expensive_segment(const float* in, float* out, size_t n) {
    // Stand-in for a deterministic layer range.
    // Replace this call with Deep2's actual layer segment dispatch.
    for (size_t i = 0; i < n; ++i) {
        float x = in[i];
        for (int k = 0; k < 400; ++k)
            x = x * 1.000001f + 0.000001f;
        out[i] = x;
    }
}

int main() {
    constexpr size_t N = 4096;
    float input[N]{};
    float output[N]{};

    for (size_t i = 0; i < N; ++i)
        input[i] = float(i % 97) * 0.001f;

    BeaconReplayCache beacon(64ull * 1024ull * 1024ull);

    SegmentDesc seg{};
    seg.model_id = 0x4E454D4F54524F4EULL; // "NEMOTRON" tag-like id
    seg.model_revision = 1;
    seg.segment_begin = 1;
    seg.segment_end = 98; // conceptual 98/99 heavy segments
    seg.config_id = 0x0000000000000001ULL;
    seg.nominal_work_units = 99;

    constexpr int iterations = 10000;

    for (int it = 0; it < iterations; ++it) {
        if (!beacon.try_replay(seg, input, sizeof(input), output, sizeof(output))) {
            expensive_segment(input, output, N);
            beacon.account_executed(seg.nominal_work_units);
            if (!beacon.commit(seg, input, sizeof(input), output, sizeof(output))) {
                std::puts("COMMIT=FAIL");
                return 2;
            }
        }
    }

    Stats s = beacon.stats();

    std::printf("=== RAWRXD_BEACONISM_99_WORK_AVOID_001 ===\n");
    std::printf("LOOKUPS=%llu\n", (unsigned long long)s.lookups);
    std::printf("HITS=%llu\n", (unsigned long long)s.hits);
    std::printf("MISSES=%llu\n", (unsigned long long)s.misses);
    std::printf("HIT_RATE_PCT=%.6f\n", s.hit_rate_pct);
    std::printf("NOMINAL_WORK_UNITS=%llu\n", (unsigned long long)s.nominal_work_units);
    std::printf("EXECUTED_WORK_UNITS=%llu\n", (unsigned long long)s.executed_work_units);
    std::printf("AVOIDED_WORK_UNITS=%llu\n", (unsigned long long)s.avoided_work_units);
    std::printf("WORK_AVOIDED_PCT=%.6f\n", s.work_avoided_pct);
    std::printf("COLLISION_REJECTS=%llu\n", (unsigned long long)s.collision_rejects);
    std::printf("VALIDATION_REJECTS=%llu\n", (unsigned long long)s.validation_rejects);

    const bool pass = s.work_avoided_pct >= 99.0 &&
                      s.validation_rejects == 0 &&
                      s.collision_rejects == 0;
    std::printf("VERDICT=%s\n", pass ? "PASS" : "HOLD");
    return pass ? 0 : 1;
}
