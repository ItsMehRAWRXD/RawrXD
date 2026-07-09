#pragma once
#include <cstdint>
#include <string>
#include <vector>

namespace seg {

enum class NodeKind : uint8_t {
    kInputToken,
    kEmbedding,
    kRMSNorm,
    kQKVProjection,
    kKVAppend,
    kAttention,
    kMLP,
    kResidual,
    kOutputProjection,
    kLogits,
    kSampleToken,
    kTelemetry,
    kCustom
};

struct NodeId {
    uint32_t value;
};

struct Edge {
    NodeId from;
    NodeId to;
};

struct Node {
    NodeId id;
    NodeKind kind;
    std::string name;

    std::vector<NodeId> inputs;
    std::vector<NodeId> outputs;

    void* user_data = nullptr; // backend-specific payload
};

} // namespace seg
