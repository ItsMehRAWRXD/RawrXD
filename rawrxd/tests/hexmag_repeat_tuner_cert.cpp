// ============================================================================
// tests/hexmag_repeat_tuner_cert.cpp  --  HEXMAG_POLYMORPHIC_REPEAT_TUNER_001
// ============================================================================
// Certification for the MASM repeat tuner.
//
// Every value printed here is an OBSERVATION returned by the linked MASM
// object.  The verdict is computed from the observations; nothing in this file
// can print PASS unless the checks it computed all held.
//
// The header is included with RAWR_HAS_MASM forced on in this translation unit:
// this cert exists precisely to prove the MASM path is live, so it asserts that
// rather than depending on the target's own compile definitions.  It includes
// the real declarations from the real header instead of re-declaring them, so
// the ABI under test is the one production callers use.
// ============================================================================
#define RAWR_HAS_MASM 1
#include "../core/hexmag_repeat_tuner.hpp"

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <vector>

namespace {

int g_total = 0;
int g_passed = 0;
int g_failed = 0;

void check(bool ok, const char* id, const std::string& detail) {
    ++g_total;
    if (ok) {
        ++g_passed;
    } else {
        ++g_failed;
    }
    // Printed exactly once, whether it passed or failed, so the receipt carries
    // the observation rather than a verdict about the observation.
    std::printf("%-4s %-32s %s\n", ok ? "ok" : "FAIL", id, detail.c_str());
}

std::string hex64(uint64_t v) {
    char buf[19];
    std::snprintf(buf, sizeof(buf), "%016llX", static_cast<unsigned long long>(v));
    return std::string(buf);
}

bool sameProfile(const HxGenProfile& a, const HxGenProfile& b) {
    return std::memcmp(&a, &b, sizeof(HxGenProfile)) == 0;
}

// ---------------------------------------------------------------------------
// T1  the ABI the MASM writes is the ABI the header declares
//
// The header does not publish field offsets, so this does not assert a table it
// invented.  It observes what the producer actually reads: every one of the 12
// packed dwords must change the fingerprint.  A dword the producer ignores is a
// dword the C++ side could write believing the tuner saw it.
// ---------------------------------------------------------------------------
void t1_layout() {
    static_assert(sizeof(HxGenProfile) == 48, "HxGenProfile must stay 48 bytes");
    check(sizeof(HxGenProfile) == 48, "T1_struct_size",
          "sizeof(HxGenProfile)=" + std::to_string(sizeof(HxGenProfile)));

    HxGenProfile zero{};
    const uint64_t fpZero = HexMag_Tuner_Fingerprint(&zero);
    int ignored = 0;
    std::string which;
    for (int word = 0; word < 12; ++word) {
        HxGenProfile p{};
        reinterpret_cast<unsigned char*>(&p)[word * 4] = 1;
        if (HexMag_Tuner_Fingerprint(&p) == fpZero) {
            ++ignored;
            which += std::to_string(word) + " ";
        }
    }
    check(ignored == 0, "T1_producer_reads_all_48",
          "dwords whose change the producer ignored: " + std::to_string(ignored) +
              (ignored ? " -> " + which : " (all 12 covered)"));
}

// ---------------------------------------------------------------------------
// T2  Init clamps the attempt budget, and Next refuses past it
// ---------------------------------------------------------------------------
void t2_budget_clamp() {
    (void)HexMag_Tuner_Init(2);
    HxGenProfile p{};
    const uint64_t at_budget = HexMag_Tuner_Next(0x1111u, HX_FAIL_WRONG, 2, &p);
    check(at_budget == 6u, "T2_budget_clamp_low",
          "Init(2) then attempt=2 -> rc=" + std::to_string(at_budget) +
              " expected HX_ERR_REPEAT(6); proves the budget is 2, not the default 8");

    (void)HexMag_Tuner_Init(1000);
    HxGenProfile q{};
    const uint64_t at_64 = HexMag_Tuner_Next(0x1111u, HX_FAIL_WRONG, 64, &q);
    check(at_64 == 6u, "T2_budget_clamp_high",
          "Init(1000) then attempt=64 -> rc=" + std::to_string(at_64) +
              " expected 6; proves the clamp at 64, since an unclamped 1000 would admit 64");

    HxGenProfile r{};
    const uint64_t below = HexMag_Tuner_Next(0x1111u, HX_FAIL_WRONG, 63, &r);
    check(below == 0u, "T2_budget_boundary",
          "attempt=63 under the clamped budget of 64 -> rc=" + std::to_string(below) +
              " expected HX_OK(0)");
}

// ---------------------------------------------------------------------------
// T3  Initial is deterministic in the request id
// ---------------------------------------------------------------------------
void t3_initial_determinism() {
    HxGenProfile a{}, b{}, c{};
    const uint64_t ra = HexMag_Tuner_Initial(0xDEADBEEFCAFEBABEull, &a);
    const uint64_t rb = HexMag_Tuner_Initial(0xDEADBEEFCAFEBABEull, &b);
    const uint64_t rc = HexMag_Tuner_Initial(0x0000000000000001ull, &c);
    check(ra == 0u && rb == 0u, "T3_rc",
          "Initial rc=" + std::to_string(ra) + "," + std::to_string(rb));
    check(sameProfile(a, b), "T3_same_hash_identical",
          "same request id -> identical 48-byte profile");
    check(!sameProfile(a, c), "T3_diff_hash_differs",
          "different request id -> different profile");

    // The baseline is DIRECT with the documented conservative parameters.
    check(a.strategy == HX_STRAT_DIRECT, "T3_initial_strategy",
          std::string("initial strategy=") + HxStrategyName(a.strategy) +
              " expected direct");
    check(a.temp_milli == 200 && a.top_p_milli == 900, "T3_initial_sampling",
          "temp_milli=" + std::to_string(a.temp_milli) +
              " top_p_milli=" + std::to_string(a.top_p_milli) + " expected 200/900");
    check(a.queue_policy == HX_QUEUE_Q_BLOCKING, "T3_initial_queue_policy",
          "queue_policy=" + std::to_string(a.queue_policy) + " expected Q_BLOCKING(1)");
}

// ---------------------------------------------------------------------------
// T4  each failure kind selects a DIFFERENT strategy
//     A tuner that returned one constant strategy would pass every other test.
// ---------------------------------------------------------------------------
void t4_strategy_per_failure_kind() {
    (void)HexMag_Tuner_Init(64);
    (void)HexMag_Tuner_Reset(0xABCDEF0123456789ull);

    struct Case { uint32_t mask; const char* name; };
    const Case cases[] = {
        {HX_FAIL_CONTRADICTION,    "contradiction"},
        {HX_FAIL_COUNTEREXAMPLE,   "counterexample"},
        {HX_FAIL_UNSUPPORTED,      "unsupported"},
        {HX_FAIL_TEST,             "test"},
        {HX_FAIL_STAGNATION,       "stagnation"},
        {HX_FAIL_WRONG,            "wrong"},
        {HX_FAIL_MISSING_INFO,     "missing_info"},
        {0u,                       "no_failure"},
    };

    std::set<uint32_t> distinct;
    std::string detail;
    for (const auto& c : cases) {
        HxGenProfile p{};
        const uint64_t rc = HexMag_Tuner_Next(0xABCDEF0123456789ull, c.mask, 0, &p);
        if (rc != 0u) {
            check(false, "T4_all_kinds_ok",
                  std::string(c.name) + " -> rc=" + std::to_string(rc));
            return;
        }
        distinct.insert(p.strategy);
        detail += std::string(c.name) + "=" + HxStrategyName(p.strategy) + " ";
    }
    check(true, "T4_all_kinds_ok", "every failure kind produced a profile");
    check(distinct.size() >= 5u, "T4_distinct_strategies",
          "distinct strategies=" + std::to_string(distinct.size()) +
              " across 8 failure kinds (" + detail + ")");

    // The documented specific mappings must hold exactly.
    HxGenProfile contra{};
    (void)HexMag_Tuner_Next(0xABCDEF0123456789ull, HX_FAIL_CONTRADICTION, 0, &contra);
    check(contra.strategy == HX_STRAT_INVARIANT && contra.temp_milli == 0,
          "T4_contradiction_mapping",
          std::string("contradiction -> ") + HxStrategyName(contra.strategy) +
              " temp_milli=" + std::to_string(contra.temp_milli) +
              " expected invariant/deterministic");

    HxGenProfile unsup{};
    (void)HexMag_Tuner_Next(0xABCDEF0123456789ull, HX_FAIL_UNSUPPORTED, 0, &unsup);
    check(unsup.strategy == HX_STRAT_EVIDENCE_GUARD && unsup.candidate_count == 1,
          "T4_unsupported_mapping",
          std::string("unsupported -> ") + HxStrategyName(unsup.strategy) +
              " candidates=" + std::to_string(unsup.candidate_count) +
              " expected evidence-guard/1");

    HxGenProfile miss{};
    (void)HexMag_Tuner_Next(0xABCDEF0123456789ull, HX_FAIL_MISSING_INFO, 0, &miss);
    check(miss.strategy == HX_STRAT_EVIDENCE_GUARD && miss.top_p_milli == 0,
          "T4_missing_info_mapping",
          std::string("missing_info -> ") + HxStrategyName(miss.strategy) +
              " top_p_milli=" + std::to_string(miss.top_p_milli) +
              " expected evidence-guard/0");
}

// ---------------------------------------------------------------------------
// T5  WRONG walks a reproducible ladder, and every generation differs
// ---------------------------------------------------------------------------
void t5_wrong_ladder_and_uniqueness() {
    (void)HexMag_Tuner_Init(64);
    (void)HexMag_Tuner_Reset(0x5A5A5A5A5A5A5A5Aull);

    std::set<uint32_t> ladder;
    std::string detail;
    for (uint32_t attempt = 0; attempt < 7; ++attempt) {
        HxGenProfile p{};
        (void)HexMag_Tuner_Next(0x5A5A5A5A5A5A5A5Aull, HX_FAIL_WRONG, attempt, &p);
        ladder.insert(p.strategy);
        detail += std::string(HxStrategyName(p.strategy)) + "/";
    }
    check(ladder.size() >= 4u, "T5_wrong_ladder_varies",
          "WRONG ladder strategies=" + std::to_string(ladder.size()) + " [" + detail + "]");

    // Reproducibility: the same (hash, mask, attempt) must give the same genome.
    HxGenProfile r1{}, r2{};
    (void)HexMag_Tuner_Next(0x5A5A5A5A5A5A5A5Aull, HX_FAIL_WRONG, 3, &r1);
    (void)HexMag_Tuner_Next(0x5A5A5A5A5A5A5A5Aull, HX_FAIL_WRONG, 3, &r2);
    check(sameProfile(r1, r2), "T5_reproducible",
          "same (hash,mask,attempt) -> identical genome across calls");

    // Uniqueness: successive generations must not collide, because the whole
    // point of the tuner is that WRONG produces a NEW generation.
    std::set<uint64_t> prints;
    for (uint32_t attempt = 0; attempt < 8; ++attempt) {
        HxGenProfile p{};
        (void)HexMag_Tuner_Next(0x5A5A5A5A5A5A5A5Aull, HX_FAIL_WRONG, attempt, &p);
        prints.insert(HexMag_Tuner_Fingerprint(&p));
    }
    check(prints.size() == 8u, "T5_fingerprints_unique",
          "8 attempts produced " + std::to_string(prints.size()) +
              " distinct fingerprints");
}

// ---------------------------------------------------------------------------
// T6  fingerprints are content-derived, not constants
// ---------------------------------------------------------------------------
void t6_fingerprint_is_content_derived() {
    HxGenProfile a{}, b{};
    (void)HexMag_Tuner_Initial(0x1111ull, &a);
    (void)HexMag_Tuner_Initial(0x2222ull, &b);
    const uint64_t fa = HexMag_Tuner_Fingerprint(&a);
    const uint64_t fb = HexMag_Tuner_Fingerprint(&b);
    const uint64_t fa2 = HexMag_Tuner_Fingerprint(&a);

    check(fa != 0u, "T6_fingerprint_nonzero", "fp(profile A)=" + hex64(fa));
    check(fa == fa2, "T6_fingerprint_stable",
          "fp is a pure function of the bytes: " + hex64(fa) + " == " + hex64(fa2));
    check(fa != fb, "T6_fingerprint_discriminates",
          "different genomes -> different fingerprints (" + hex64(fa) + " vs " +
              hex64(fb) + ")");
    check(HexMag_Tuner_Fingerprint(nullptr) == 0u, "T6_fingerprint_null",
          "fp(nullptr)=" + hex64(HexMag_Tuner_Fingerprint(nullptr)) + " expected 0");

    // A single flipped bit in the profile must change the fingerprint, which is
    // what makes the fingerprint usable as a genome identity.
    HxGenProfile mutated = a;
    mutated.mutation_nonce ^= 1u;
    check(HexMag_Tuner_Fingerprint(&mutated) != fa, "T6_fingerprint_bit_sensitive",
          "one flipped nonce bit changes the fingerprint");
}

// ---------------------------------------------------------------------------
// T7  Reset mints a new generation id; the id actually moves
// ---------------------------------------------------------------------------
void t7_generation_id_moves() {
    (void)HexMag_Tuner_Init(4);
    (void)HexMag_Tuner_Reset(0xAAAAull);
    const uint64_t g0 = HexMag_Tuner_GenerationId();
    (void)HexMag_Tuner_Reset(0xBBBBull);
    const uint64_t g1 = HexMag_Tuner_GenerationId();
    HxGenProfile p{};
    (void)HexMag_Tuner_Next(0xBBBBull, HX_FAIL_WRONG, 0, &p);
    const uint64_t g2 = HexMag_Tuner_GenerationId();
    check(g1 != g0 && g2 != g1, "T7_generation_moves",
          "generation ids " + std::to_string(g0) + " -> " + std::to_string(g1) +
              " -> " + std::to_string(g2));
}

// ---------------------------------------------------------------------------
// T8  GetProfile mirrors the last produced genome, and counters track it
// ---------------------------------------------------------------------------
void t8_get_profile_and_counters() {
    (void)HexMag_Tuner_Init(16);
    (void)HexMag_Tuner_Reset(0xCCCCull);
    HxGenProfile produced{};
    (void)HexMag_Tuner_Next(0xCCCCull, HX_FAIL_TEST, 0, &produced);

    HxGenProfile mirrored{};
    const uint64_t rc = HexMag_Tuner_GetProfile(&mirrored);
    check(rc == 0u, "T8_get_profile_rc", "GetProfile rc=" + std::to_string(rc));
    check(sameProfile(produced, mirrored), "T8_get_profile_mirrors",
          std::string("mirrored strategy=") + HxStrategyName(mirrored.strategy) +
              " matches the produced genome");

    check(HexMag_Tuner_Attempt() == 1u, "T8_attempt_counter",
          "attempt after one Next(attempt=0) = " +
              std::to_string(HexMag_Tuner_Attempt()) + " expected 1");
    check(HexMag_Tuner_Strategy() == produced.strategy, "T8_strategy_view",
          std::string("strategy view=") + HxStrategyName(HexMag_Tuner_Strategy()) +
              " matches produced strategy");
}

// ---------------------------------------------------------------------------
// T9  null out-pointers are rejected, never dereferenced
// ---------------------------------------------------------------------------
void t9_null_rejected() {
    const uint64_t a = HexMag_Tuner_Initial(0x1ull, nullptr);
    const uint64_t b = HexMag_Tuner_Next(0x1ull, HX_FAIL_WRONG, 0, nullptr);
    const uint64_t c = HexMag_Tuner_GetProfile(nullptr);
    check(a == 4u && b == 4u && c == 4u, "T9_null_rejected",
          "Initial/Next/GetProfile(null) rc=" + std::to_string(a) + "," +
              std::to_string(b) + "," + std::to_string(c) + " expected 4,4,4");
}

// ---------------------------------------------------------------------------
// T10 the persistent weight delta is 0 by construction
// ---------------------------------------------------------------------------
void t10_weight_delta_zero() {
    (void)HexMag_Tuner_Init(8);
    (void)HexMag_Tuner_Reset(0xEEEEull);
    uint32_t samples[4] = {0, 0, 0, 0};
    samples[0] = HexMag_Tuner_WeightDelta();
    HxGenProfile p{};
    (void)HexMag_Tuner_Next(0xEEEEull, HX_FAIL_WRONG, 0, &p);
    samples[1] = HexMag_Tuner_WeightDelta();
    (void)HexMag_Tuner_Next(0xEEEEull, HX_FAIL_STAGNATION, 1, &p);
    samples[2] = HexMag_Tuner_WeightDelta();
    (void)HexMag_Tuner_Reset(0xEEEEull);
    samples[3] = HexMag_Tuner_WeightDelta();
    const bool allZero = samples[0] == 0u && samples[1] == 0u &&
                         samples[2] == 0u && samples[3] == 0u;
    check(allZero, "T10_weight_delta_zero",
          "WeightDelta samples = " + std::to_string(samples[0]) + "," +
              std::to_string(samples[1]) + "," + std::to_string(samples[2]) + "," +
              std::to_string(samples[3]) +
              "; the tuner owns a request-local genome and no weight bytes");
}

// ---------------------------------------------------------------------------
// T11 POSITIVE CONTROL -- the gate must be able to reach PASS on real behaviour
// ---------------------------------------------------------------------------
void t11_positive_control() {
    // A real, expected-correct escalation: TEST failure -> REPAIR, wider budget.
    (void)HexMag_Tuner_Init(3);
    (void)HexMag_Tuner_Reset(0x0F0F0F0F0F0F0F0Full);
    HxGenProfile p{};
    const uint64_t rc = HexMag_Tuner_Next(0x0F0F0F0F0F0F0F0Full, HX_FAIL_TEST, 0, &p);
    const bool ok = rc == 0u && p.strategy == HX_STRAT_REPAIR &&
                    p.blocking_passes == 1 && p.candidate_count == 2;
    check(ok, "T11_positive_control",
          std::string("TEST failure -> ") + HxStrategyName(p.strategy) +
              " blocking_passes=" + std::to_string(p.blocking_passes) +
              " candidates=" + std::to_string(p.candidate_count) +
              " rc=" + std::to_string(rc) + " expected repair/1/2/0");

    // And the budget boundary in the positive direction: exactly max is refused,
    // max-1 is accepted.
    HxGenProfile q{};
    const uint64_t last = HexMag_Tuner_Next(0x0F0F0F0F0F0F0F0Full, HX_FAIL_TEST, 2, &q);
    HxGenProfile r{};
    const uint64_t past = HexMag_Tuner_Next(0x0F0F0F0F0F0F0F0Full, HX_FAIL_TEST, 3, &r);
    check(last == 0u && past == 6u, "T11_budget_boundary_positive",
          "attempt=2 accepted(rc=" + std::to_string(last) + "), attempt=3 refused(rc=" +
              std::to_string(past) + ") under Init(3)");
}

} // namespace

int main() {
    // Unbuffered: if this tool crashes mid-run the output captured so far must
    // survive, otherwise a crash produces an empty file that looks like a run
    // that printed nothing rather than one that died.
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::printf("=== HEXMAG_POLYMORPHIC_REPEAT_TUNER_001 ===\n");
    std::printf("BACKEND=MASM (linked object, not a stub)\n");

    t1_layout();
    t2_budget_clamp();
    t3_initial_determinism();
    t4_strategy_per_failure_kind();
    t5_wrong_ladder_and_uniqueness();
    t6_fingerprint_is_content_derived();
    t7_generation_id_moves();
    t8_get_profile_and_counters();
    t9_null_rejected();
    t10_weight_delta_zero();
    t11_positive_control();

    std::printf("CHECKS_TOTAL=%d\n", g_total);
    std::printf("CHECKS_PASS=%d\n", g_passed);
    std::printf("CHECKS_FAIL=%d\n", g_failed);

    if (g_failed == 0) {
        std::printf("VERDICT=PASS\n");
        return 0;
    }
    std::printf("VERDICT=FAIL\n");
    return 1;
}
