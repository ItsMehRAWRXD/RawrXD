// Logic test for the deterministic polymorphic engine (Package 3, partial).
// Verifies: deterministic replay, ratio effect, zero RNG (by construction).
#include "PolymorphicEngine.hpp"
#include <cstdio>
#include <vector>

using namespace rawrxd::poly;
static int g_fails = 0;
static void ck(bool ok, const char* n) { std::printf("%s %s\n", ok?"OK":"FAIL", n); if(!ok) ++g_fails; }

static std::vector<Cand> Run(const Ratio& r) {
    State s; s.bestBatch = 64; s.bestThreads = 8;
    std::vector<Cand> seq;
    for (int i = 0; i < 12; ++i) {
        seq.push_back(NextCandidate(r, s));
        s.step++; s.predErr = (i % 3); s.stagnation = i;
        if (i == 6) { s.bestDecode = 220.0; s.curDecode = 210.0; } // observation
    }
    return seq;
}

int main() {
    Ratio r; // 50 50 (neutral)
    auto a = Run(r);
    auto b = Run(r);                 // replay from identical observations
    bool replay = (a == b);
    ck(replay, "deterministic_replay");

    Ratio r2; r2.set(20, 80);        // runtime ratio change
    auto c = Run(r2);
    bool ratioEffect = false;
    for (size_t i = 0; i < a.size(); ++i)
        if (!(a[i] == c[i])) { ratioEffect = true; break; }
    ck(ratioEffect, "ratio_changes_behavior");

    // Different observations -> different behavior.
    State s1; s1.bestBatch = 64; s1.bestThreads = 8; s1.stagnation = 0; s1.predErr = 0;
    State s2 = s1; s2.stagnation = 9; s2.predErr = 5; // different observed state
    bool obsEffect = !(NextCandidate(r, s1) == NextCandidate(r, s2)) ||
                     (SelectStrategy(r, s1) != SelectStrategy(r, s2));
    ck(obsEffect, "observations_change_strategy");

    std::printf("RATIO_50_50 valid=%d\n", r.valid());
    std::printf("sample: batch=%d thr=%d | batch=%d thr=%d\n",
        a[0].batch, a[0].threads, a[3].batch, a[3].threads);
    std::printf("FAILS=%d\n", g_fails);
    return g_fails ? 1 : 0;
}