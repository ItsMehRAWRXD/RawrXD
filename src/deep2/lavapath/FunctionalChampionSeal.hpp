#pragma once
/*
    RAWRXD_FUNCTIONAL_CHAMPION_001
    RAWRXD_TPS_KILLER_SEAL_001

    Full generation decides promotion.

    Current functional champion:
        ~3.556 TPS

    Product performance seal:
        >= 5.000 TPS
        <= 12.8 sec / 64 tokens

    DO_NOT_REOPEN:
        KvaInversion
        KVA climb
        Batch007
*/

#include "GenerationParity.hpp"

#include <array>
#include <cstdint>
#include <cstdio>

namespace rawrxd::deep2::champion {

constexpr uint32_t kSealTokens = 64;
constexpr double   kProductFloorTps = 5.000;
constexpr uint64_t kProductWallMaxNs = 12'800'000'000ULL;

struct StageExposure {
    const char* name = "NONE";
    const char* owner = "NONE";
    uint64_t exposedUs = 0;
};

struct Candidate {
    const char* model = "UNKNOWN";
    const char* path = "generateStream";

    uint32_t tokensRequested = 0;
    uint32_t tokensCommitted = 0;

    uint64_t generationWallNs = 0;
    double decodeTpsReal = 0.0;

    // Candidate must come from the real product run.
    bool measuredReal = false;
    bool syntheticGeneration = false;
    bool microOnlyResult = false;
    bool sameChampionProvenance = false;

    parity::Input parity{};

    std::array<StageExposure, 10> exposure{};
    uint32_t exposureCount = 0;
};

struct ExistingChampion {
    double decodeTpsReal = 3.556;
    uint64_t generationWallNs = 17'997'750'000ULL;
};

struct Decision {
    bool functionalPass = false;
    bool parityPass = false;

    bool beatsChampion = false;
    bool candidateKilled = true;

    bool functionalChampion = false;
    bool productTpsSeal = false;

    const char* blockedAt = "UNKNOWN";

    StageExposure spinCloseBlocker{};
};

inline StageExposure LargestExposure(const Candidate& c) noexcept {
    StageExposure best{};

    const uint32_t n =
        c.exposureCount < c.exposure.size()
            ? c.exposureCount
            : static_cast<uint32_t>(c.exposure.size());

    for (uint32_t i = 0; i < n; ++i) {
        if (c.exposure[i].exposedUs > best.exposedUs)
            best = c.exposure[i];
    }

    return best;
}

inline Decision Evaluate(
    const Candidate& c,
    const ExistingChampion& current = {}) noexcept
{
    Decision d{};
    d.spinCloseBlocker = LargestExposure(c);

    // Absolutely no promotion from component/micro results.
    if (!c.measuredReal ||
        c.syntheticGeneration ||
        c.microOnlyResult) {
        d.blockedAt = "NOT_REAL_PRODUCT_GENERATION";
        return d;
    }

    if (!c.sameChampionProvenance &&
        c.tokensRequested == kSealTokens) {
        d.blockedAt = "PROVENANCE_MISMATCH";
        return d;
    }

    const auto p = parity::Evaluate(c.parity);
    d.parityPass = p.pass;

    if (!p.pass) {
        d.blockedAt = p.blockedAt;
        return d;
    }

    if (c.tokensRequested == 0 ||
        c.tokensCommitted != c.tokensRequested) {
        d.blockedAt = "TOKENS_COMMITTED";
        return d;
    }

    d.functionalPass = true;

    /* Champion / product TPS seals require exact 64-token product run. */
    if (c.tokensRequested != kSealTokens ||
        c.tokensCommitted != kSealTokens) {
        d.candidateKilled = true;
        d.blockedAt = "64_TOKEN_PRODUCT_RUN";
        return d;
    }

    /*
       Regression killer.

       Functional candidates are allowed to execute,
       but a slower candidate cannot replace the champion.
    */
    d.beatsChampion =
        c.decodeTpsReal > current.decodeTpsReal &&
        c.generationWallNs < current.generationWallNs;

    d.candidateKilled = !d.beatsChampion;

    if (d.beatsChampion)
        d.functionalChampion = true;

    /*
       Product seal is stronger than "new champion".

       >= 5 TPS and <= 12.8 sec must both be measured
       in the same real 64-token generation.
    */
    d.productTpsSeal =
        d.functionalPass &&
        d.parityPass &&
        c.decodeTpsReal >= kProductFloorTps &&
        c.generationWallNs <= kProductWallMaxNs;

    if (d.productTpsSeal) {
        d.candidateKilled = false;
        d.functionalChampion = true;
        d.blockedAt = "NONE";
    } else if (!d.beatsChampion) {
        d.blockedAt = "CHAMPION_REGRESSION";
    } else {
        d.blockedAt = "WALL_WITHIN_BUDGET";
    }

    return d;
}

inline void Emit(
    FILE* f,
    const Candidate& c,
    const Decision& d) noexcept
{
    if (!f)
        return;

    std::fprintf(f,
        "RAWRXD_FUNCTIONAL_CHAMPION_001\n"
        "RAWRXD_TPS_KILLER_SEAL_001\n");

    std::fprintf(f,
        "MODEL=%s\n"
        "PATH=%s\n"
        "TOKENS_REQUESTED=%u\n"
        "TOKENS_COMMITTED=%u\n",
        c.model,
        c.path,
        c.tokensRequested,
        c.tokensCommitted);

    std::fprintf(f,
        "GENERATION_WALL_NS=%llu\n"
        "DECODE_TPS_REAL=%.6f\n"
        "PRODUCT_FLOOR_TPS=%.3f\n"
        "PRODUCT_WALL_MAX_NS=%llu\n",
        static_cast<unsigned long long>(c.generationWallNs),
        c.decodeTpsReal,
        kProductFloorTps,
        static_cast<unsigned long long>(kProductWallMaxNs));

    std::fprintf(f,
        "PARITY_PASS=%d\n"
        "FUNCTIONAL_PASS=%d\n"
        "CANDIDATE_BEATS_CHAMPION=%d\n"
        "CANDIDATE_KILLED=%d\n"
        "FUNCTIONAL_CHAMPION=%d\n"
        "TPS_PRODUCT_SEAL=%d\n",
        d.parityPass ? 1 : 0,
        d.functionalPass ? 1 : 0,
        d.beatsChampion ? 1 : 0,
        d.candidateKilled ? 1 : 0,
        d.functionalChampion ? 1 : 0,
        d.productTpsSeal ? 1 : 0);

    std::fprintf(f,
        "SPIN_CLOSE_BLOCKER=%s\n"
        "SPIN_CLOSE_BLOCKER_OWNER=%s\n"
        "SPIN_CLOSE_BLOCKER_US=%llu\n",
        d.spinCloseBlocker.name,
        d.spinCloseBlocker.owner,
        static_cast<unsigned long long>(
            d.spinCloseBlocker.exposedUs));

    std::fprintf(f,
        "BLOCKED_AT=%s\n",
        d.blockedAt);

    std::fprintf(f,
        "DO_NOT_REOPEN=KvaInversion\n"
        "DO_NOT_REOPEN=KVA_CLIMB\n"
        "DO_NOT_REOPEN=BATCH_007\n");

    if (d.productTpsSeal) {
        std::fprintf(f,
            "RAWRXD_PERFORMANCE_001=PASS\n"
            "RAWRXD_PRODUCT_TPS_001=PASS\n");
    } else {
        std::fprintf(f,
            "RAWRXD_PERFORMANCE_001=OPEN\n"
            "RAWRXD_PRODUCT_TPS_001=OPEN\n");
    }

    std::fprintf(f,
        "RECEIPT_END=RAWRXD_TPS_KILLER_SEAL_001\n");
}

} // namespace rawrxd::deep2::champion
