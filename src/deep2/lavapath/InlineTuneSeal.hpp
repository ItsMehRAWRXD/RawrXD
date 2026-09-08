#pragma once
/* Inline tune state — sealed once per generation, winner persists. */
#include "ZeroStarContract.hpp"
#include <cstdint>

namespace rawr::inline_tune {

struct Seal {
    uint64_t generationId = 0;
    uint32_t tokenPosition = 0;
    uint32_t sealed = 0;
    uint32_t winnerRows = 0;
    uint32_t parityOk = 0;
    uint32_t measured = 0;
    uint64_t wallUs = 0;
};

inline bool SameGeneration(const Seal& s, uint64_t genId,
                           uint32_t tokPos) noexcept {
    return s.generationId == genId && s.tokenPosition == tokPos;
}

inline bool MayPromote(const Seal& s) noexcept {
    return PARITY_BEFORE_PROMOTION && MEASURE_BEFORE_WINNER && s.parityOk &&
           s.measured && s.winnerRows > 0;
}

} // namespace rawr::inline_tune
