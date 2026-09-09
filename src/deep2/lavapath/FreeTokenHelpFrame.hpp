#pragma once
/* HelpFrame — B+ underused opening vs public dual-only ping-pong.
 * PreScope/SP-MoE pay ~2%: double buffer L / L+1.
 * We run N-way (>2): COMPUTE | HELP1 | HELP2 | FILL across dual sticks.
 * Same fixed addresses; role rotates; never realloc. */
#include "FreeTokenMicroZone.hpp"
#include <cstdint>
#include <cstdio>

namespace Deep2 {
namespace freetoken {

enum class FrameRole : uint8_t {
    Compute = 0,
    Help1   = 1, /* L+1 predicted experts */
    Help2   = 2, /* L+2 speculative help */
    Fill    = 3, /* disk→zone fill while compute runs */
    Count   = 4
};

inline uint32_t RoleToStick(FrameRole r, uint32_t layer) {
    /* Dual GPU rub × role parity → up to 4-way freak without new alloc. */
    const uint32_t role = static_cast<uint32_t>(r) & 3u;
    return ((layer & 1u) ^ (role >> 1)) | ((role & 1u) << 1);
}

/* Reserve zone for help-frame overwrite; returns zone idx or ~0u. */
inline uint32_t ScheduleHelp(uint32_t targetLayer, FrameRole role) {
    if (!Pool().live) return ~0u;
    uint32_t stick = RoleToStick(role, targetLayer) %
                     (Pool().stickCount ? Pool().stickCount : 4);
    return PickZone(stick);
}

inline void EmitHelpWitness(FILE* f, uint32_t layer, uint32_t nHelp1,
                            uint32_t nHelp2) {
    if (!f) f = stderr;
    std::fprintf(f,
        "FREETOKEN_HELPFRAME layer=%u help1=%u help2=%u nway=%u "
        "roles=COMPUTE|HELP1|HELP2|FILL eat_gt2=1 "
        "public_gap=prescope_dual_only\n",
        layer, nHelp1, nHelp2,
        Pool().stickCount ? Pool().stickCount : 4u);
}

} // namespace freetoken
} // namespace Deep2
