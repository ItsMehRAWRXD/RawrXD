#include "HexMagRepeatTunerBridge.hpp"

#include <cstdint>
#include <cstdio>
#include <set>

using namespace rawrxd::agentic::hexmag;

static int fail(const char* what) {
    std::fprintf(stderr, "[FAIL] %s\n", what);
    return 1;
}

int main() {
    RepeatSession session(0xA55A1234DEADBEEFull, 6);
    if (!session.valid()) return fail("initial session invalid");
    if (session.fingerprint() == 0) return fail("initial fingerprint zero");
    if (session.generationId() == 0) return fail("initial generation_id zero");
    if (session.profile().blockingPasses != 3) return fail("blocking_passes != 3");
    if (session.profile().queuePolicy != HX_QUEUE_Q_BLOCKING) return fail("queue_policy != Q_BLOCKING");
    if (HexMag_Tuner_WeightDelta() != 0) return fail("persistent weight delta nonzero");

    std::set<std::uint64_t> fingerprints{session.fingerprint()};
    std::set<std::uint64_t> generations{session.generationId()};

    const auto advanceAndCheck = [&](std::uint32_t mask, std::uint32_t expectedStrategy) -> bool {
        if (!session.advance(mask)) return false;
        if (!fingerprints.insert(session.fingerprint()).second) return false;
        if (!generations.insert(session.generationId()).second) return false;
        if (session.profile().blockingPasses != 3) return false;
        if (session.profile().queuePolicy != HX_QUEUE_Q_BLOCKING) return false;
        if (HexMag_Tuner_WeightDelta() != 0) return false;
        if (session.profile().strategy != expectedStrategy) return false;
        return true;
    };

    // Generic verifier WRONG must trigger a real alternate reasoning strategy.
    if (!advanceAndCheck(HX_FAIL_WRONG, HX_STRAT_REVERSE))
        return fail("generic WRONG did not mutate to reverse/falsifier");

    // Build/test failures must use the repair specialist.
    if (!advanceAndCheck(HX_FAIL_WRONG | HX_FAIL_TEST, HX_STRAT_REPAIR))
        return fail("TEST did not mutate to repair");

    // Unsupported claims must trigger reverse assumption-breaking.
    if (!advanceAndCheck(HX_FAIL_WRONG | HX_FAIL_UNSUPPORTED, HX_STRAT_REVERSE))
        return fail("UNSUPPORTED did not mutate to reverse");

    // Missing information must fail closed with evidence guard and temp=0.
    if (!advanceAndCheck(HX_FAIL_WRONG | HX_FAIL_MISSING_INFO, HX_STRAT_EVIDENCE_GUARD))
        return fail("MISSING_INFO did not mutate to evidence guard");
    if (session.profile().tempMilli != 0)
        return fail("MISSING_INFO temperature was not zero");
    if (session.profile().candidateCount != 1)
        return fail("MISSING_INFO candidate_count was not one");

    // One final retry remains for maxAttempts=6 (initial + attempts 1..5).
    if (!session.advance(HX_FAIL_WRONG | HX_FAIL_STAGNATION))
        return fail("final allowed retry unexpectedly exhausted");
    if (!fingerprints.insert(session.fingerprint()).second)
        return fail("final fingerprint duplicated");
    if (!generations.insert(session.generationId()).second)
        return fail("final generation_id duplicated");

    // Attempt 6 must exhaust: never fake success.
    if (session.advance(HX_FAIL_WRONG))
        return fail("retry exhaustion did not fail closed");

    std::printf(
        "HEXMAG_POLYMORPHIC_REPEAT_TUNER_001=PASS\n"
        "unique_fingerprints=%zu\n"
        "unique_generation_ids=%zu\n"
        "blocking_passes=3\n"
        "queue_policy=Q_BLOCKING\n"
        "persistent_weight_delta_bytes=0\n"
        "exhaustion=INSUFFICIENT_INFORMATION\n",
        fingerprints.size(), generations.size());
    return 0;
}
