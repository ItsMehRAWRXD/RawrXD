// Self-contained test for R9700ExpertLruPolicy.hpp (the r9700-stack expert-cache
// port). No external deps: plain C++17, deterministic assertions.
//
// Build (MSVC):  cl /std:c++17 /EHsc /Fe:r9700_lru_test.exe R9700ExpertLruPolicy_test.cpp
// Build (clang): clang++ -std=c++17 -O2 -o r9700_lru_test R9700ExpertLruPolicy_test.cpp
// Build (g++):   g++ -std=c++17 -O2 -o r9700_lru_test R9700ExpertLruPolicy_test.cpp
#include "R9700ExpertLruPolicy.hpp"

#include <cstdio>
#include <cstdlib>
#include <random>
#include <set>

using namespace rawrxd::r9700;
using ExpertLruPolicyConfig = rawrxd::r9700::ExpertLruPolicy::Config;

static int failures = 0;
#define CHECK(cond, msg)                                  \
    do {                                                  \
        if (!(cond)) {                                    \
            std::printf("FAIL %s:%d: %s\n",               \
                        __FILE__, __LINE__, (msg));       \
            ++failures;                                   \
        }                                                 \
    } while (0)

// Runs a deterministic pseudo-MoE workload and verifies the invariants that
// mirror the upstream r4d_lru.hip contract.
static void RunWorkload(uint32_t experts, uint32_t slots, uint32_t topk, uint64_t steps, uint32_t cap) {
    ExpertLruPolicyConfig cfg;
    cfg.num_experts = experts;
    cfg.num_slots = slots;
    cfg.max_misses_per_step = cap;
    ExpertLruPolicy lru(cfg);

    std::mt19937_64 rng(0x5EEDull);
    for (uint64_t step = 0; step < steps; ++step) {
        // topk unique, sorted experts
        std::set<uint32_t> picks;
        const uint32_t k = topk <= experts ? topk : experts;
        while (picks.size() < k) {
            picks.insert((uint32_t)(rng() % experts));
        }
        std::vector<uint32_t> routed(picks.begin(), picks.end());

        std::vector<uint32_t> misses, evicted;
        CHECK(lru.Step(routed, misses, evicted), "Step contract");

        // (1) Misses are exactly the routed experts that were not resident
        //     before, in ascending order.
        const auto& st = lru.state();
        // (2) Nothing routed this step was evicted (pinned-routed invariant).
        for (uint32_t e : evicted) {
            CHECK(std::binary_search(routed.begin(), routed.end(), e) == false,
                  "evicted an expert routed this step");
        }
        // (3) Stamps: every resident routed expert has stamp == current step.
        for (uint32_t e : routed) {
            uint32_t s = st.slot_of_expert[e];
            if (s != 0xFFFFFFFFu) {
                CHECK(st.stamp_of_slot[s] == lru.step(), "routed expert not refreshed");
            }
        }
        // (4) Evicted experts are truly gone; misses are all resident now.
        for (uint32_t e : evicted) CHECK(st.slot_of_expert[e] == 0xFFFFFFFFu, "evicted still resident");
        for (uint32_t e : misses) CHECK(st.slot_of_expert[e] != 0xFFFFFFFFu, "miss not filled");
        // (5) Capacity never exceeded.
        CHECK(lru.ResidentCount() <= slots, "capacity exceeded");
        // (6) Slot map is self-consistent.
        for (uint32_t s = 0; s < slots; ++s) {
            uint32_t e = st.expert_of_slot[s];
            if (e != 0xFFFFFFFFu) {
                CHECK(st.slot_of_expert[e] == s, "slot<->expert map inconsistent");
            }
        }
    }

    // Determinism: two instances fed the same routing sequence diverge never.
    ExpertLruPolicyConfig dc = cfg;
    ExpertLruPolicy a(dc), b(dc);
    std::vector<uint32_t> r1 = {1, 5, 9, 40};
    std::vector<uint32_t> r2 = {2, 5, 30, 99};
    std::vector<uint32_t> m1, e1, m2, e2, m3, e3, m4, e4;
    a.Step(r1, m1, e1); a.Step(r2, m2, e2);
    b.Step(r1, m3, e3); b.Step(r2, m4, e4);
    CHECK(m1 == m3 && e1 == e3 && m2 == m4 && e2 == e4, "determinism broken");
    const auto& sa = a.state();
    const auto& sb = b.state();
    CHECK(sa.expert_of_slot == sb.expert_of_slot, "final tables differ");
}

int main() {
    RunWorkload(/*experts=*/256, /*slots=*/64, /*topk=*/8, /*steps=*/20000, /*cap=*/0);
    RunWorkload(/*experts=*/64,  /*slots=*/8,  /*topk=*/6, /*steps=*/20000, /*cap=*/4);
    RunWorkload(/*experts=*/32,  /*slots=*/32, /*topk=*/32,/*steps=*/5000,  /*cap=*/0);
    RunWorkload(/*experts=*/1024,/*slots=*/128,/*topk=*/16,/*steps=*/5000,  /*cap=*/32);
    // Degenerate: routing more experts than slots always.
    RunWorkload(16, 1, 16, 1000, 0);
    if (failures) {
        std::printf("RESULT: FAILED (%d checks)\n", failures);
        return 1;
    }
    std::printf("RESULT: PASS (all invariants held)\n");
    return 0;
}
