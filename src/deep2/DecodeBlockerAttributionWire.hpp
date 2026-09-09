#pragma once
// ============================================================================
// DecodeBlockerAttributionWire.hpp
// Source-only Deep2 drop 002: small guard wrappers for wiring Reset / scopes / Emit
// alongside the isolation ladder without mutating decode semantics.
// ============================================================================

#include "DecodeBlockerAttribution.hpp"
#include <cstdlib>
#include <cstdio>

namespace Deep2::decode_blocker_wire {

inline bool Enabled() noexcept {
    const char* e = std::getenv("RAWRXD_DECODE_BLOCKER_ATTRIBUTION");
    return e && e[0] == '1';
}

inline const char* IgnoredOwner() noexcept {
    const char* e = std::getenv("RAWRXD_ISO_IGNORE_OWNER");
    return (e && e[0]) ? e : "NONE";
}

inline void ResetIfEnabled(std::uint64_t requested) noexcept {
    if (Enabled()) Deep2::decode_blocker::Reset(requested);
}

inline void EmitIfEnabled(FILE* f, double totalWallMs, double prefillMs, double decodeMs) noexcept {
    if (Enabled()) Deep2::decode_blocker::Emit(f ? f : stderr, totalWallMs, prefillMs, decodeMs, IgnoredOwner());
}

} // namespace Deep2::decode_blocker_wire

#define RAWR_DECODE_SCOPE_IF_ENABLED(kind) \
    Deep2::decode_blocker::Scope _rawr_decode_scope_##kind(Deep2::decode_blocker::A().kind##Ms)
