// ============================================================================
// src/core/context_config.h -- Context admission limits and resolution
// ============================================================================
// Declares RawrXD::ContextLimits, ContextResolveHints, ContextDecision,
// UnifiedContextConfig and the two free resolve functions.
//
// ----------------------------------------------------------------------------
// WHY THIS FILE EXISTS NOW (RAWRXD_MISSING_SOURCE_001)
// ----------------------------------------------------------------------------
// Two translation units in this tree open with this header and neither header
// nor file was ever written. src/core/gold_link_closure.cpp:20 fails to compile
// without it, and gold_link_closure.cpp IS in the RawrXD_Gold source list:
//
//     src\core\gold_link_closure.cpp(20,10): error C1083: Cannot open include
//         file: 'context_config.h': No such file or directory
//
// As with support_tier.h, the build-graph census cannot see this: it scans
// CMakeLists.txt for declared SOURCES, and a missing #include is not a
// source-list entry.
//
// ----------------------------------------------------------------------------
// ONE PLACE IN THIS FILE IS A JUDGEMENT CALL, AND IT IS MARKED
// ----------------------------------------------------------------------------
// Every type, field and signature below was read off a use site. The seven
// ContextLimits CONSTANT VALUES could not be: no definition of them survives
// anywhere in the tree (searched all of F:\~dev\rawrxd for both the identifier
// and plausible token counts). They are therefore chosen, not recovered, and
// they are tagged UNMEASURED so the next reader does not mistake a policy
// decision for a recovered fact. They are chosen to be self-consistent with the
// only comparisons that do survive:
//
//   - getSystemSafeMax buckets DOWNWARD through the ladder with `>=`, so the
//     order TINY < STANDARD < LARGE < XL < FLAGSHIP is fixed by the code.
//   - forModel maps phi-3/llama-3/qwen to LARGE, tiny/mini to XL, everything
//     else to STANDARD, and floors to TINY under 8 GiB VRAM.
//   - forModel turns on KV offload at `context_limit >= LARGE`.
//
// On this host (64 GB RAM, 32 GB VRAM) getSystemSafeMax computes
// min(VRAM, RAM/2) = 33.5 GB, /131072 B/token = 255900 tokens, *0.8 = 204720,
// which lands at FLAGSHIP. If the intended ladder differs, admission decisions
// differ with it and nothing else in the code will notice.
//
// ----------------------------------------------------------------------------
// A SECOND MISSING HEADER IS NOT ADDRESSED HERE
// ----------------------------------------------------------------------------
// src/core/context_config.cpp also includes "vram_probe.h", which is likewise
// absent repo-wide. That file was NOT reconstructed: context_config.cpp is not
// compiled by any project in this build tree (verified against every .vcxproj),
// so the absence does not block a build, and inventing a VRAM probe interface
// with no implementation behind it would add an unverifiable surface. The
// absence is recorded, not papered over.
// ============================================================================

#pragma once

#include <cstdint>
#include <string>

namespace RawrXD {

// ============================================================================
// Context Limits
// ============================================================================
// A class of static constants plus three static helpers. No instances exist and
// none are needed; ContextLimits::estimateKVBytes is called as a static from
// both this header's consumers.
class ContextLimits {
public:
    // --- The ladder ---------------------------------------------------------
    // UNMEASURED: values chosen, not recovered. See the header note. The
    // ordering is load-bearing (getSystemSafeMax compares with `>=`).
    static constexpr int32_t TINY     = 2048;
    static constexpr int32_t STANDARD = 8192;
    static constexpr int32_t LARGE    = 32768;
    static constexpr int32_t XL       = 65536;
    static constexpr int32_t FLAGSHIP = 131072;

    // Requested context when the caller does not ask for anything specific.
    static constexpr int32_t DEFAULT = 4096;

    // KV footprint assumed per token when the caller does not supply one:
    // 2 tensors (K and V) x 32 layers x 8 kv-heads x 128 head_dim x 2 bytes
    // = 131072. UNMEASURED for the same reason as the ladder above.
    static constexpr int64_t DEFAULT_KV_BYTES_PER_TOKEN = 131072;

    // Bucket a memory budget down to the nearest rung of the ladder.
    // getSystemSafeMax uses a flat 0.8 safety factor and DEFAULT_KV_BYTES_PER_TOKEN.
    static int32_t getSystemSafeMax(int64_t vramBytes, int64_t ramBytes);

    // Bucket using an explicit per-token cost and safety margin. Clamps the
    // margin to (0, 1] and the per-token cost to the default when non-positive,
    // and falls back to TINY for any budget too small to hold one token.
    static int32_t getKVSafeMax(int64_t vramBytes,
                                int64_t ramBytes,
                                int64_t kvBytesPerToken = DEFAULT_KV_BYTES_PER_TOKEN,
                                float   safetyMargin   = 0.8f);

    // 0 for a non-positive token count; otherwise tokens x per-token cost with
    // the same non-positive-cost fallback as getKVSafeMax.
    static int64_t estimateKVBytes(int32_t contextTokens,
                                   int64_t kvBytesPerToken = DEFAULT_KV_BYTES_PER_TOKEN);

private:
    ContextLimits() = delete;
};

// ============================================================================
// Context Resolve Hints
// ============================================================================
// Caller-supplied pressure signals. Every field is read through a clamp helper
// in context_config.cpp (clampScale / clampThreshold), so a default-constructed
// ContextResolveHints is a valid "no hint" value: ResolveContextDecision builds
// exactly that and relies on it.
struct ContextResolveHints {
    // Positive values override the derived budget.
    int64_t explicit_kv_budget_bytes = 0;

    // Fractional scalers, clamped to a floor of 0.5 by clampScale.
    float   latency_scale   = 1.0f;
    float   pressure_scale  = 1.0f;
    float   pressure_threshold = 0.9f;   // clamped by clampThreshold

    bool    latency_sensitive = false;
};

// ============================================================================
// Context Decision
// ============================================================================
// The result of resolving a requested context against the memory budget.
//
// EVERY MEMBER IS DEFAULT-INITIALISED, and that is load-bearing rather than
// stylistic: gold_link_closure.cpp:403 declares a bare `ContextDecision` and
// assigns only five of these thirteen fields before returning it. Without
// initialisers the remaining eight are indeterminate, and a caller reading
// decision.pressure_ratio would be reading stack garbage.
struct ContextDecision {
    // Requested vs. admitted.
    int32_t requested = 0;             // after any environment override
    int32_t effective = 0;             // what is actually granted

    // Rungs of the ladder this decision was measured against.
    int32_t system_safe_max = 0;
    int32_t kv_safe_max     = 0;

    // Budgets, in bytes.
    int64_t vram_budget_bytes = 0;
    int64_t kv_budget_bytes   = 0;

    // Measured footprint and the ratio that produced the pressure verdict.
    int64_t estimated_kv_bytes = 0;
    double  pressure_ratio     = 0.0;
    double  kv_bytes_per_token = 0.0;

    // Verdicts and their inputs.
    bool   pressure_detected     = false;
    bool   adapted               = false;   // effective was reduced from requested
    bool   env_override_applied  = false;
    int32_t env_override_value   = 0;
};

// ============================================================================
// Unified Context Config
// ============================================================================
// Per-model context policy. forModel() picks a rung from the model name, then
// lowers it if the available VRAM is small, then hands the result to
// ResolveContextDecision for a final clamp.
struct UnifiedContextConfig {
    int32_t context_limit = ContextLimits::DEFAULT;
    bool    use_kv_quantization = false;
    bool    enable_kv_offload    = false;

    static UnifiedContextConfig forModel(const std::string& modelName,
                                         int64_t availableVramBytes);
};

// ============================================================================
// Resolution Entry Points
// ============================================================================
// ResolveContextDecisionWithHints is the real implementation; ResolveContextDecision
// is the no-hints convenience wrapper. context_config.cpp:408 calls
// ResolveContextDecision with only two arguments, which is why the trailing
// parameters carry defaults.
ContextDecision ResolveContextDecisionWithHints(int32_t              requested,
                                                const ContextResolveHints& hints,
                                                int64_t              vramBytes  = 0,
                                                int64_t              ramBytes   = 0,
                                                const char*          envVarName = nullptr);

ContextDecision ResolveContextDecision(int32_t     requested,
                                       int64_t     vramBytes  = 0,
                                       int64_t     ramBytes   = 0,
                                       const char* envVarName = nullptr);

} // namespace RawrXD