// ============================================================================
// engine_link_supplement.cpp — minimal, honest definitions for a small set of
// engine-referenced symbols whose full translation units are (a) absent from
// the curated tree, or (b) written against a diverged fork's headers.
//
// These are deliberately conservative: they let rawrxd_deep2_engine link and
// run headless, and they route every guarded feature to its safe default
// (host fallback / telemetry-off) instead of fabricating success.
// ============================================================================

namespace rawrxd {
// AMD GPU power telemetry is not wired into this engine build. Report it as
// unavailable so power-biased placement policy takes its conservative default
// rather than acting on readings this build cannot produce. (Matches the raw
// GpuDecodeEfficiency.cpp intent, whose translation unit depends on a config
// header absent from the engine target.)
bool AmdGpuPowerTelemetryAvailable() noexcept { return false; }
bool GpuPowerValidForPolicy() noexcept { return false; }
} // namespace rawrxd

#include "K2NativeStreamGate.hpp"

// K2NativeStreamGate::Run — the native K2 shard streaming forward path. The
// full gate (Q4_K embed + streamed MLA layers + Q6_K logits) lives in a large
// translation unit built against a diverged fork; here we provide the contract
// entry point so the engine links, returning a fail-closed Result. Callers
// treat ok=false as "native gate not selected" and fall back to the standard
// engine forward path, which is the certified baseline.
namespace K2NativeStreamGate {
Result Run(const std::filesystem::path& /*shardDir*/,
           const Deep2::GlobalTensorIndex& /*index*/,
           const Deep2::KimiK2Config& /*k2cfg*/,
           const std::vector<std::filesystem::path>& /*shards*/,
           const Config& /*cfg*/) {
    Result r;
    r.ok = false;
    r.error = "K2NativeStreamGate::Run: native shard-streaming gate not linked "
              "in this build; using standard engine forward path.";
    return r;
}
} // namespace K2NativeStreamGate
