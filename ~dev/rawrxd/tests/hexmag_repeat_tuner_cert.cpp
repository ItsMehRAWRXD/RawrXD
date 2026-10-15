// hexmag_repeat_tuner_cert.cpp — HEXMAG_POLYMORPHIC_REPEAT_TUNER_001
// Certifies: genome mutation produces WRONG; persistent_weight_delta_bytes == 0; generation_id advances

#include "core/hexmag_repeat_tuner.hpp"
#include <cstdio>
#include <cstdint>

bool testInit() {
    uint64_t req = HexMag_Tuner_Init(3);
    return req != 0;
}

bool testReset() {
    uint64_t req = 0xDEADBEEFCAFEBABEULL;
    uint64_t gen = HexMag_Tuner_Reset(req);
    return gen == 1;
}

bool testInitialProfile() {
    uint64_t req = 0x123456789ABCDEF0ULL;
    HexMag_Tuner_Reset(req);
    HxGenProfile p{};
    uint64_t gen = HexMag_Tuner_Initial(req, &p);
    if (gen != 1) return false;
    // direct strategy, valid ranges
    if (p.strategy != 0) return false; // HX_STRAT_DIRECT
    if (p.candidate_count == 0) return false;
    if (p.blocking_passes != 3) return false;
    if (p.queue_policy != 1) return false; // HX_QUEUE_Q_BLOCKING
    return true;
}

bool testNextMutation() {
    uint64_t req = 0x5555555555555555ULL;
    HexMag_Tuner_Reset(req);
    HxGenProfile p{};
    HexMag_Tuner_Initial(req, &p);
    uint32_t gen0 = p.mutation_nonce;
    // Simulate WRONG failure
    uint64_t gen = HexMag_Tuner_Next(req, 0x0040, 1, &p); // HX_FAIL_WRONG
    if (gen != 2) return false;
    if (p.mutation_nonce == gen0) return false; // must mutate
    if (p.strategy == 0) return false; // should not stay direct
    return true;
}

bool testWeightDeltaZero() {
    uint32_t delta = HexMag_Tuner_WeightDelta();
    return delta == 0;
}

bool testGenerationAdvances() {
    uint64_t req = 0xAAAAAAAAAAAAAAAAULL;
    HexMag_Tuner_Reset(req);
    HxGenProfile p{};
    HexMag_Tuner_Initial(req, &p);
    uint64_t gen1 = HexMag_Tuner_GenerationId();
    HexMag_Tuner_Next(req, 0x0040, 1, &p); // WRONG
    uint64_t gen2 = HexMag_Tuner_GenerationId();
    return gen2 == gen1 + 1;
}

bool testFingerprintChanges() {
    uint64_t req = 0xBBBBBBBBBBBBBBBBULL;
    HexMag_Tuner_Reset(req);
    HxGenProfile p{};
    HexMag_Tuner_Initial(req, &p);
    uint64_t fp1 = HexMag_Tuner_Fingerprint(&p);
    HexMag_Tuner_Next(req, 0x0040, 1, &p); // WRONG
    uint64_t fp2 = HexMag_Tuner_Fingerprint(&p);
    return fp2 != fp1;
}

bool testExhaustion() {
    uint64_t req = 0xCCCCCCCCCCCCCCCCULL;
    HexMag_Tuner_Reset(req);
    HxGenProfile p{};
    HexMag_Tuner_Initial(req, &p);
    for (uint32_t a = 1; a <= 3; ++a) {
        uint64_t gen = HexMag_Tuner_Next(req, 0x0040, a, &p); // WRONG
        if (gen != a + 1) return false;
    }
    // 4th attempt should still mutate but indicate exhausted
    uint64_t gen = HexMag_Tuner_Next(req, 0x0040, 4, &p);
    return gen == 5;
}

int main() {
    int pass = 0, fail = 0;
    auto run = [&](const char* name, bool (*fn)()) {
        bool ok = fn();
        std::printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
        if (ok) ++pass; else ++fail;
    };
    run("init", testInit);
    run("reset", testReset);
    run("initial_profile", testInitialProfile);
    run("next_mutation", testNextMutation);
    run("weight_delta_zero", testWeightDeltaZero);
    run("generation_advances", testGenerationAdvances);
    run("fingerprint_changes", testFingerprintChanges);
    run("exhaustion", testExhaustion);
    std::printf("\nVERDICT=%s pass=%d fail=%d\n", fail == 0 ? "PASS" : "FAIL", pass, fail);
    return fail == 0 ? 0 : 1;
}