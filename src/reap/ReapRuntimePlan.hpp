#pragma once

// Runtime REAP default is non-destructive residency + router top-k. Optional
// physicalExclude remaps router cardinality to a retained expert set and
// excludes pruned experts from the execute path; it still never rewrites GGUF.
// Offline physical repack remains ReapMoETransformer (admission-gated).

#include <cstdint>
#include <string>
#include <string_view>

namespace RawrXD::Reap {

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
};

struct RuntimeInjection {
    uint64_t parameterCount = 0;
    uint64_t expertCount = 0;
    uint64_t workingSetBytes = 0;
    bool enabled = false;
    // When true: expertCount = retained expert cardinality; router is remapped
    // to that set and pruned experts are excluded from load/execute. Still does
    // not rewrite GGUF (sourceImmutable). Offline repack remains separate.
    bool physicalExclude = false;
};

struct RuntimeInjectionReceipt {
    bool active = false;
    bool routeConfigured = false;
    bool streamerConfigured = false;
    bool workingSetConfigured = false;
    bool sourceImmutable = true;
    bool physicalExclude = false;
    bool residencyOnly = true;
    uint64_t requestedParameters = 0;
    uint64_t requestedExperts = 0;
    uint64_t effectiveExperts = 0;
    uint64_t retainedExperts = 0;
    uint64_t workingSetBytes = 0;
    std::string status = "NOT_CONFIGURED";
    std::string reason;
};

// Parse <parameters>/<experts>, for example 30B/8, 1T/384, or 4096M/8E.
// The parser has no product-size ceiling.  It rejects only malformed values
// and uint64 overflow; physical topology admission is a separate runtime gate.
bool ParseRuntimeTarget(std::string_view text, RuntimeTarget& out,
                        std::string& error);

// Read model geometry without modifying or rewriting the source model.
bool InspectRuntimeModel(const std::string& firstShard,
                         RuntimeModelFacts& out, std::string& error);

bool BuildRuntimePlan(const std::string& firstShard,
                      const RuntimeTarget& target,
                      RuntimePlan& out, std::string& error);

std::string RuntimePlanJson(const RuntimePlan& plan);

} // namespace RawrXD::Reap
