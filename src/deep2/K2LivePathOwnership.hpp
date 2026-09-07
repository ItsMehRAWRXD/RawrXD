// K2LivePathOwnership.hpp — one tensor → one owner
// Trampoline: output.weight reuse only (pinned)
// Cyclone: blk.* deadline/prefetch acquire when layer WS fits
// Elastic: blk.* miss recovery — promote only when not already live
#pragma once
#include "Deep2LivePath.hpp"
#include <cstring>

namespace Deep2 {

inline bool K2LiveCache_OwnsOutput() {
    return LivePath_Active() && LivePath_EnhancementsEnabled() &&
           LivePath_MechOn(LP_MECH_TRAMPOLINE);
}
inline bool K2LiveCache_OwnsLayer() {
    return LivePath_Active() && LivePath_EnhancementsEnabled() &&
           (LivePath_MechOn(LP_MECH_CYCLONE) || LivePath_MechOn(LP_MECH_ELASTIC));
}
inline bool K2LiveCache_IsOutputName(const char* n) {
    return n && std::strcmp(n, "output.weight") == 0;
}
inline bool K2LiveCache_IsLayerName(const char* n) {
    return n && n[0] == 'b' && n[1] == 'l' && n[2] == 'k' && n[3] == '.';
}
inline bool K2LiveCache_IsMlaAttnName(const char* n) {
    if (!n) return false;
    return std::strstr(n, ".attn_q_a") || std::strstr(n, ".attn_q_b") ||
           std::strstr(n, ".attn_kv_a") || std::strstr(n, ".attn_k_b") ||
           std::strstr(n, ".attn_v_b") || std::strstr(n, ".attn_kv_b") ||
           std::strstr(n, ".attn_output") || std::strstr(n, ".attn_norm");
}
inline bool K2LiveCache_MayCache(const char* name) {
    if (K2LiveCache_IsOutputName(name)) return K2LiveCache_OwnsOutput();
    if (K2LiveCache_IsLayerName(name)) {
        if (K2LiveCache_OwnsLayer()) return true;
        // GPU MLA pin path: host sticky MLA attn even without cyclone arm.
        if (K2LiveCache_IsMlaAttnName(name)) {
            const char* g = std::getenv("DEEP2_K2_GPU_MLA");
            if (g && g[0] == '1') return true;
        }
        return false;
    }
    // Trampoline also pins tiny decode companions (not cyclone layer WS).
    if (K2LiveCache_OwnsOutput() && name &&
        std::strcmp(name, "output_norm.weight") == 0)
        return true;
    return false;
}
// When trampoline shares budget, layer fill needs rem >= perLayer * activeDepth
// (RAWRXD_K2_LAYERS), not a fictional full-61 WS reserve.
bool K2LiveCache_LayerHostFillAllowed();

} // namespace Deep2
