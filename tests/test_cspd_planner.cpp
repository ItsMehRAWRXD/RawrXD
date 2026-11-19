// ============================================================================
// CSPD Stage 1 -- standalone planner + reducer test.
//
// Build (x64 Native Tools prompt, from the repo root):
//   cl /nologo /std:c++17 /EHsc /O2 /I src\deep2 ^
//     tests\test_cspd_planner.cpp /Fe:tmp_build\cspd_test.exe
//   tmp_build\cspd_test.exe
//
// Checks:
//   P1 planner table (chunking, split clamping, tail, single-split fallback)
//   P2 split_ranges (even division, remainder, clamping)
//   P3 adaptive selector (compute-bound, overhead-bound, mixed curves)
//   P4 randomized numerical parity: unsplit vs split reduction (1e-9)
//   P5 all-masked context -> zero output, l == 0
//   P6 uneven chunk boundaries (context not a multiple of the chunk size)
//   P7 determinism (bit-identical repeat)
// ============================================================================
#include <cmath>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <random>
#include <vector>

#include "cspd/context_parallel_plan.hpp"
#include "cspd/split_kv_attention.hpp"

using rawrxd::cspd::ContextParallelPlan;
using rawrxd::cspd::attention_chunk;
using rawrxd::cspd::merge_partials;
using rawrxd::cspd::plan_context_parallel;
using rawrxd::cspd::select_splits_adaptive;
using rawrxd::cspd::split_kv_attention;
using rawrxd::cspd::split_ranges;

static int g_failures = 0;

#define CHECK(cond, msg)                                                    \
    do {                                                                    \
        if (!(cond)) {                                                      \
            std::printf("FAIL %s (line %d)\n", msg, __LINE__);              \
            ++g_failures;                                                   \
        }                                                                   \
    } while (0)

static void test_planner_table() {
    struct Row { std::size_t ctx, maxSplits, chunks, splits, tail; };
    const Row rows[] = {
        {0, 8, 1, 1, 0},        // empty context: one empty chunk
        {4096, 8, 1, 1, 0},     // exact single chunk
        {4097, 8, 2, 2, 1},     // one token into the second chunk
        {16384, 8, 4, 4, 0},    // 16K -> 4 chunks
        {32768, 8, 8, 8, 0},    // 32K -> 8 chunks
        {64 * 1000, 8, 16, 8, 2560},  // 64K -> 16 chunks (15x4096 + 2560), capped to 8 splits
        {5000, 8, 2, 2, 904},   // uneven tail
        {64 * 1000, 0, 16, 1, 2560},  // maxSplits <= 0 clamps to 1
        {10, 4, 1, 1, 10},      // context smaller than one chunk
    };
    for (const Row& r : rows) {
        const ContextParallelPlan p = plan_context_parallel(r.ctx, r.maxSplits);
        if (p.logicalChunks != r.chunks || p.parallelSplits != r.splits ||
            p.tailTokens != r.tail || p.contextTokens != r.ctx) {
            std::printf("FAIL planner ctx=%zu maxSplits=%zu -> chunks=%zu splits=%zu tail=%zu\n",
                        r.ctx, r.maxSplits, p.logicalChunks, p.parallelSplits, p.tailTokens);
            ++g_failures;
        }
        CHECK(p.singleSplitFallback() == (r.splits <= 1), "singleSplitFallback flag");
    }
    std::printf("P1 planner table: %d rows ok\n", (int)(sizeof(rows) / sizeof(rows[0])));
}

static void test_split_ranges() {
    const auto r10 = split_ranges(10, 3);
    CHECK(r10.size() == 3, "10/3 -> 3 ranges");
    CHECK(r10[0].first == 0 && r10[0].second == 3, "10/3 range0");
    CHECK(r10[1].first == 3 && r10[1].second == 6, "10/3 range1");
    CHECK(r10[2].first == 6 && r10[2].second == 10, "10/3 range2 (remainder)");

    const auto r7 = split_ranges(7, 3);
    CHECK(r7.size() == 3 && r7[2].second == 7, "7/3 coverage");

    const auto r1 = split_ranges(5, 9);  // splits > context clamps to 5
    CHECK(r1.size() == 5, "splits clamp to context");

    CHECK(split_ranges(0, 4).empty(), "empty context -> no ranges");
    std::printf("P2 split_ranges: ok\n");
}

static void test_adaptive_selector() {
    const std::size_t ctx = 64 * 1000;  // 16 logical chunks at 4096
    // Compute-bound: more splits always faster -> picks the cap (8).
    const std::size_t s1 = select_splits_adaptive(ctx, 8, [](std::size_t s) {
        return 1000.0 / static_cast<double>(s);
    });
    CHECK(s1 == 8, "compute-bound picks max splits");

    // Overhead-bound: fewer splits always faster -> picks 1.
    const std::size_t s2 = select_splits_adaptive(ctx, 8, [](std::size_t s) {
        return 10.0 + 2.0 * static_cast<double>(s);
    });
    CHECK(s2 == 1, "overhead-bound picks single split");

    // Mixed: time(s) = 100/s + 2*s -> minimum at s=7 (100/49=2.04 vs 2*7=14;
    // compare s=7: 16.3, s=8: 16.5, s=6: 16.7+... -> minimum at 7).
    const std::size_t s3 = select_splits_adaptive(ctx, 8, [](std::size_t s) {
        return 100.0 / static_cast<double>(s) + 2.0 * static_cast<double>(s);
    });
    CHECK(s3 == 7, "mixed curve picks interior minimum");

    // Ties keep the smaller split count.
    const std::size_t s4 = select_splits_adaptive(ctx, 8, [](std::size_t) { return 5.0; });
    CHECK(s4 == 1, "ties keep fewer splits");

    // Deterministic fallback: context with a single chunk never exceeds 1.
    const std::size_t s5 = select_splits_adaptive(4096, 8, [](std::size_t) { return 1.0; });
    CHECK(s5 == 1, "single chunk -> single split");
    std::printf("P3 adaptive selector: ok\n");
}

static void test_numerical_parity() {
    std::mt19937 rng(12345);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    const std::size_t rank = 16, vStride = 16, context = 4096;
    std::vector<float> q(rank), k(context * rank), v(context * vStride);
    for (auto& x : q) x = dist(rng);
    for (auto& x : k) x = dist(rng);
    for (auto& x : v) x = dist(rng);

    const std::vector<double> ref = split_kv_attention(q.data(), k.data(), v.data(),
                                                       nullptr, rank, context, 1, vStride);
    const std::size_t splitsToTry[] = {2, 3, 5, 8, 16, 64};
    double worst = 0.0;
    for (std::size_t s : splitsToTry) {
        const std::vector<double> got = split_kv_attention(q.data(), k.data(), v.data(),
                                                           nullptr, rank, context, s, vStride);
        CHECK(got.size() == ref.size(), "output size");
        for (std::size_t j = 0; j < ref.size(); ++j) {
            worst = std::max(worst, std::fabs(got[j] - ref[j]));
        }
    }
    CHECK(worst < 1e-9, "parity within 1e-9");
    std::printf("P4 randomized parity: splits {2,3,5,8,16,64}, worst |diff| = %.3e\n", worst);

    // Determinism: bit-identical repeat.
    const std::vector<double> again = split_kv_attention(q.data(), k.data(), v.data(),
                                                         nullptr, rank, context, 5, vStride);
    const std::vector<double> again2 = split_kv_attention(q.data(), k.data(), v.data(),
                                                          nullptr, rank, context, 5, vStride);
    CHECK(std::memcmp(again.data(), again2.data(), again.size() * sizeof(double)) == 0,
          "deterministic output");
    std::printf("P7 determinism: ok\n");
}

static void test_all_masked() {
    std::mt19937 rng(777);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    const std::size_t rank = 8, vStride = 8, context = 100;
    std::vector<float> q(rank), k(context * rank), v(context * vStride);
    for (auto& x : q) x = dist(rng);
    for (auto& x : k) x = dist(rng);
    for (auto& x : v) x = dist(rng);
    // Contiguous bool storage (std::vector<bool> has no .data()).
    auto noneValid = std::make_unique<bool[]>(context);   // zero-init: all false
    const std::vector<double> out = split_kv_attention(q.data(), k.data(), v.data(),
                                                       noneValid.get(), rank, context, 4, vStride);
    for (double x : out) CHECK(x == 0.0, "all-masked -> zero output");
    std::printf("P5 all-masked: ok\n");

    // Partially masked: masked positions must not affect the output.
    auto halfValid = std::make_unique<bool[]>(context);
    for (std::size_t i = 0; i < context; ++i) halfValid[i] = true;
    for (std::size_t t = 0; t < context; t += 2) halfValid[t] = false;
    const std::vector<double> masked = split_kv_attention(q.data(), k.data(), v.data(),
                                                          halfValid.get(), rank, context, 4, vStride);
    // Equivalent: build a compacted context keeping only odd rows.
    std::vector<float> k2, v2;
    for (std::size_t t = 1; t < context; t += 2) {
        for (std::size_t r = 0; r < rank; ++r) k2.push_back(k[t * rank + r]);
        for (std::size_t j = 0; j < vStride; ++j) v2.push_back(v[t * vStride + j]);
    }
    const std::vector<double> compacted = split_kv_attention(q.data(), k2.data(), v2.data(),
                                                             nullptr, rank, context / 2, 4, vStride);
    double worst = 0.0;
    for (std::size_t j = 0; j < vStride; ++j) {
        worst = std::max(worst, std::fabs(masked[j] - compacted[j]));
    }
    CHECK(worst < 1e-9, "masked == compacted parity");
    std::printf("P5b partial masking: worst |diff| = %.3e\n", worst);
}

static void test_uneven_boundaries() {
    std::mt19937 rng(999);
    std::uniform_real_distribution<float> dist(-1.0f, 1.0f);
    const std::size_t rank = 8, vStride = 8;
    double worst = 0.0;
    for (std::size_t context : {7u, 13u, 1023u, 4097u, 5000u}) {
        std::vector<float> q(rank), k(context * rank), v(context * vStride);
        for (auto& x : q) x = dist(rng);
        for (auto& x : k) x = dist(rng);
        for (auto& x : v) x = dist(rng);
        const std::vector<double> ref = split_kv_attention(q.data(), k.data(), v.data(),
                                                           nullptr, rank, context, 1, vStride);
        for (std::size_t s : {2u, 3u, 7u}) {
            if (s > context) continue;
            const std::vector<double> got = split_kv_attention(q.data(), k.data(), v.data(),
                                                               nullptr, rank, context, s, vStride);
            for (std::size_t j = 0; j < ref.size(); ++j) {
                worst = std::max(worst, std::fabs(got[j] - ref[j]));
            }
        }
    }
    CHECK(worst < 1e-9, "uneven boundaries parity");
    std::printf("P6 uneven boundaries: worst |diff| = %.3e\n", worst);
}

int main() {
    test_planner_table();
    test_split_ranges();
    test_adaptive_selector();
    test_numerical_parity();
    test_all_masked();
    test_uneven_boundaries();
    if (g_failures == 0) {
        std::printf("CSPD STAGE 1: ALL TESTS PASS\n");
        return 0;
    }
    std::printf("CSPD STAGE 1: %d FAILURES\n", g_failures);
    return 1;
}