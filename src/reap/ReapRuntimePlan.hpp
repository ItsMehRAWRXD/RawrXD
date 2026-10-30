#pragma once

// Runtime REAP is a non-destructive execution policy.  It changes the
// resident expert working set and router top-k for the current engine session;
// it never rewrites GGUF bytes.  The older candidate-writer path remains
// separate and is intentionally not called by this interface.

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
