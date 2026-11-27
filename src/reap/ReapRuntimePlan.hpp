#pragma once

// Runtime REAP is a non-destructive execution policy.  It changes the
// resident expert working set and router top-k for the current engine session;
// it never rewrites GGUF bytes.  The older candidate-writer path remains
// separate and is intentionally not called by this interface.

#include <cstdint>
#include <string>
#include <string_view>

#include "deep2/ReapExpertSelection.hpp"

namespace RawrXD::Reap {

// RP01: authoritative transformation mode (controls actual execution, not a flag).
enum class TransformMode : uint8_t { Physical = 0, Virtual = 1, Streaming = 2 };

static inline bool ParseTransformMode(std::string_view s, TransformMode& out) {
    if (s == "PHYSICAL")  { out = TransformMode::Physical;  return true; }
    if (s == "VIRTUAL")   { out = TransformMode::Virtual;   return true; }
    if (s == "STREAMING") { out = TransformMode::Streaming; return true; }
    return false;   // reject invalid/unsupported mode explicitly
}
static inline const char* TransformModeName(TransformMode m) noexcept {
    switch (m) {
        case TransformMode::Physical:  return "PHYSICAL";
        case TransformMode::Virtual:   return "VIRTUAL";
        case TransformMode::Streaming: return "STREAMING";
    }
    return "INVALID";
}

struct RuntimeTarget {
    uint64_t parameterCount = 0;
    uint64_t expertCount = 0;
    std::string source;
};

struct RuntimeModelFacts {
    std::string model;
    std::string architecture;
    uint64_t parameterCount = 0;
    uint64_t tensorBytes = 0;
    uint64_t expertCount = 0;
    uint64_t expertsPerToken = 0;
    uint64_t layerCount = 0;
    uint32_t shardCount = 0;
    uint64_t tensorCount = 0;
};

struct RuntimePlan {
    static constexpr const char* kSchema =
        "rawrxd.reap.runtime_injection.v1";

    RuntimeTarget requested{};
    RuntimeModelFacts actual{};
    uint64_t targetWorkingSetBytes = 0;
    std::string direction = "UNKNOWN";
    std::string injectionMode = "STREAMER_HOTPATCH";
    std::string streamerPath = "MoEWeightProxy+VulkanPrefetch";
    std::string status = "NOT_ADMITTED";
    std::string reason;
    bool sourceImmutable = true;
    bool writerInvoked = false;
    // Authoritative transformation mode (RP01). Single source of truth; the
    // former duplicate string `mode` field was removed (A07 consolidation).
    TransformMode transformMode = TransformMode::Physical;
    // V06.1: authoritative per-layer retained-expert selection (original order).
    // Empty = no selection (Physical may derive from activeExperts; Virtual/Streaming
    // require it). Expert counts derive from this, not a duplicate scalar.
    Selection selection;
};

struct RuntimeInjection {
    uint64_t parameterCount = 0;
    uint64_t expertCount = 0;
    uint64_t workingSetBytes = 0;
    bool enabled = false;
    // V06.1: authoritative per-layer selection propagated to ingestion. When
    // hasSelection is true, expertCount must equal the per-layer selection size
    // (validated); Virtual/Streaming consume `selection` to transform/acquire the
    // exact retained experts in original order.
    bool hasSelection = false;
    Selection selection;
};

struct RuntimeInjectionReceipt {
    bool active = false;
    bool routeConfigured = false;
    bool streamerConfigured = false;
    bool workingSetConfigured = false;
    bool sourceImmutable = true;
    uint64_t requestedParameters = 0;
    uint64_t requestedExperts = 0;
    uint64_t effectiveExperts = 0;
    uint64_t workingSetBytes = 0;
    bool selectionValidated = false;  // V06.3: per-layer selection validated at ingestion
    std::string status = "NOT_CONFIGURED";
    std::string reason;
};

// Parse <parameters>/<experts>, for example 30B/8, 1T/384, or 4096M/8E.
// The parser has no product-size ceiling.  It rejects only malformed values
// and uint64 overflow; physical topology admission is a separate runtime gate.
bool ParseRuntimeTarget(std::string_view text, RuntimeTarget& out,
                        std::string& error);

// V06.1: derive the per-layer retained expert count from the authoritative
// selection. Returns 0 and sets uniform=false when layers disagree or empty.
uint64_t SelectionExpertCount(const Selection& selection, bool& uniform);

// V06.1: validate the selection (reuse ValidateSelection) and, when activeExperts>0,
// that its uniform per-layer count matches. Fail-closed on missing/duplicate/
// out-of-range/incompatible selections.
bool ValidateRuntimeSelection(const Selection& selection, uint64_t activeExperts,
                              std::string& error);

// Read model geometry without modifying or rewriting the source model.
bool InspectRuntimeModel(const std::string& firstShard,
                         RuntimeModelFacts& out, std::string& error);

bool BuildRuntimePlan(const std::string& firstShard,
                      const RuntimeTarget& target,
                      RuntimePlan& out, std::string& error);

std::string RuntimePlanJson(const RuntimePlan& plan);

} // namespace RawrXD::Reap
