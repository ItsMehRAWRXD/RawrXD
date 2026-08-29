// ============================================================================
// hexmag_repeat_tuner.hpp — MASM polymorphic repeat tuner (no Python)
// ============================================================================
// Mirrors RawrXD_HexMag_RepeatTuner.asm + HEXMAG_POLYMORPHIC_REPEAT_TUNER_001.
//   WRONG != same generation; WRONG == mutate genome -> new generation_id
//   persistent_weight_delta_bytes = 0 (request-local only)
// ============================================================================
#ifndef RAWRXD_HEXMAG_REPEAT_TUNER_HPP
#define RAWRXD_HEXMAG_REPEAT_TUNER_HPP

#include <cstdint>

constexpr uint32_t HX_STRAT_DIRECT         = 0;
constexpr uint32_t HX_STRAT_DECOMPOSE      = 1;
constexpr uint32_t HX_STRAT_REVERSE        = 2;
constexpr uint32_t HX_STRAT_COUNTEREXAMPLE = 3;
constexpr uint32_t HX_STRAT_INVARIANT      = 4;
constexpr uint32_t HX_STRAT_REPAIR         = 5;
constexpr uint32_t HX_STRAT_EVIDENCE_GUARD = 6;

constexpr uint32_t HX_FAIL_CONTRADICTION = 0x0001;
constexpr uint32_t HX_FAIL_COUNTEREXAMPLE = 0x0002;
constexpr uint32_t HX_FAIL_UNSUPPORTED   = 0x0004;
constexpr uint32_t HX_FAIL_TEST          = 0x0008;
constexpr uint32_t HX_FAIL_STAGNATION    = 0x0010;
constexpr uint32_t HX_FAIL_MISSING_INFO  = 0x0020;
constexpr uint32_t HX_FAIL_WRONG         = 0x0040;

constexpr uint32_t HX_QUEUE_Q_BLOCKING = 1;

#pragma pack(push, 1)
struct HxGenProfile {
    uint32_t strategy;
    uint32_t specialist;
    uint32_t temp_milli;              // 200 => 0.20
    uint32_t top_p_milli;             // 900 => 0.90
    uint32_t candidate_count;
    uint32_t reverse_depth;
    uint32_t counterexample_budget;
    uint32_t invariant_budget;
    uint32_t blocking_passes;         // 3 on retries
    uint32_t queue_policy;            // Q_BLOCKING
    uint32_t mutation_nonce;
    uint32_t _pad0;
};
#pragma pack(pop)
static_assert(sizeof(HxGenProfile) == 48, "HxGenProfile size");

#ifdef RAWR_HAS_MASM
extern "C" {
    uint64_t HexMag_Tuner_Init(uint32_t max_attempts);
    uint64_t HexMag_Tuner_Reset(uint64_t request_id_hash);
    uint64_t HexMag_Tuner_Initial(uint64_t request_id_hash, HxGenProfile* out_opt);
    uint64_t HexMag_Tuner_Next(uint64_t request_id_hash, uint32_t fail_kind_mask,
                               uint32_t attempt, HxGenProfile* out_opt);
    uint64_t HexMag_Tuner_Fingerprint(const HxGenProfile* profile);
    uint64_t HexMag_Tuner_GenerationId();
    uint64_t HexMag_Tuner_GetProfile(HxGenProfile* out);
    uint32_t HexMag_Tuner_WeightDelta();  // always 0
    uint32_t HexMag_Tuner_Attempt();
    uint32_t HexMag_Tuner_Strategy();
}
#endif

inline const char* HxStrategyName(uint32_t s) {
    switch (s) {
        case HX_STRAT_DIRECT:         return "direct";
        case HX_STRAT_DECOMPOSE:      return "decompose";
        case HX_STRAT_REVERSE:        return "reverse";
        case HX_STRAT_COUNTEREXAMPLE: return "counterexample";
        case HX_STRAT_INVARIANT:      return "invariant";
        case HX_STRAT_REPAIR:         return "repair";
        case HX_STRAT_EVIDENCE_GUARD: return "evidence-guard";
        default:                      return "unknown";
    }
}

#endif // RAWRXD_HEXMAG_REPEAT_TUNER_HPP
