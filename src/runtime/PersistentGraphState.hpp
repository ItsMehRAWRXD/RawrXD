#pragma once
// RawrXD Persistent Graph State
// Fixed irreducible math graph + dynamic persistent values.
// C++17, Windows, no third-party dependencies.

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <cstdint>
#include <string>
#include <vector>

namespace rawrxd::runtime {

enum class ValueType : uint8_t {
    U32 = 1,
    U64 = 2,
    I64 = 3,
    F32 = 4,
    F64 = 5,
    Bool = 6
};

enum ValueFlags : uint32_t {
    Value_None          = 0,
    Value_Configurable  = 1u << 0,
    Value_Persistent    = 1u << 1,
    Value_RuntimeOnly   = 1u << 2,
    Value_ReadOnly      = 1u << 3,
    Value_PerToken      = 1u << 4,
    Value_PerLayer      = 1u << 5,
    Value_PerSequence   = 1u << 6
};

union ValueBits {
    uint32_t u32;
    uint64_t u64;
    int64_t  i64;
    float    f32;
    double   f64;
    uint8_t  boolean;
};

struct PersistentValue {
    uint64_t id;
    ValueType type;
    uint8_t reserved0[3];
    uint32_t flags;
    ValueBits value;
    ValueBits default_value;
    ValueBits min_value;
    ValueBits max_value;
};

enum class MathOp : uint16_t {
    Input = 1,
    Embed,
    Norm,
    Q,
    K,
    V,
    Attention,
    OProj,
    Residual,
    FFNGate,
    FFNUp,
    FFNDown,
    MoERouter,
    MoEExpert,
    Logits,
    Sample,
    Emit
};

struct GraphNode {
    uint64_t node_id;
    MathOp op;
    uint16_t layer;
    uint32_t first_dependency;
    uint16_t dependency_count;
    uint16_t first_value;
    uint16_t value_count;
    uint16_t reserved;
};

struct GraphDependency {
    uint32_t producer_node;
    uint32_t consumer_node;
};

#pragma pack(push, 1)
struct SnapshotHeader {
    char magic[8];          // "RXPGS001"
    uint32_t version;       // 1
    uint32_t header_bytes;
    uint64_t graph_hash;
    uint64_t generation;
    uint32_t value_count;
    uint32_t value_bytes;
    uint64_t payload_hash;
};
#pragma pack(pop)

class PersistentGraphState final {
public:
    bool Build(
        const GraphNode* nodes, uint32_t node_count,
        const GraphDependency* deps, uint32_t dep_count,
        const PersistentValue* values, uint32_t value_count) noexcept;

    bool ValidateGraph() const noexcept;

    uint64_t GraphHash() const noexcept { return graph_hash_; }
    uint64_t Generation() const noexcept { return generation_; }

    PersistentValue* Find(uint64_t id) noexcept;
    const PersistentValue* Find(uint64_t id) const noexcept;

    bool SetU32(uint64_t id, uint32_t v) noexcept;
    bool SetU64(uint64_t id, uint64_t v) noexcept;
    bool SetI64(uint64_t id, int64_t v) noexcept;
    bool SetF32(uint64_t id, float v) noexcept;
    bool SetF64(uint64_t id, double v) noexcept;
    bool SetBool(uint64_t id, bool v) noexcept;

    bool GetU32(uint64_t id, uint32_t* out) const noexcept;
    bool GetU64(uint64_t id, uint64_t* out) const noexcept;
    bool GetI64(uint64_t id, int64_t* out) const noexcept;
    bool GetF32(uint64_t id, float* out) const noexcept;
    bool GetF64(uint64_t id, double* out) const noexcept;
    bool GetBool(uint64_t id, bool* out) const noexcept;

    // Binary snapshot: fast, exact, versioned, graph-bound.
    bool SaveSnapshot(const wchar_t* path) const noexcept;
    bool LoadSnapshot(const wchar_t* path, bool require_same_graph = true) noexcept;

    // Human-readable overrides: id=value, decimal or 0x hex for integers.
    bool ApplyConfigFile(const wchar_t* path) noexcept;

    // Decode current persistent state to stable TSV.
    bool DumpDecoded(const wchar_t* path) const noexcept;

    // Reset configurable persistent values to their declared defaults.
    void ResetDefaults() noexcept;

    const std::vector<GraphNode>& Nodes() const noexcept { return nodes_; }
    const std::vector<GraphDependency>& Dependencies() const noexcept { return deps_; }
    const std::vector<PersistentValue>& Values() const noexcept { return values_; }

    static uint64_t StableId(const char* text) noexcept;

private:
    static uint64_t Hash64(const void* data, size_t bytes) noexcept;
    static bool IsInRange(const PersistentValue& p, const ValueBits& v) noexcept;
    static bool CanConfigure(const PersistentValue& p) noexcept;

    bool SetRaw(uint64_t id, ValueType type, ValueBits v) noexcept;
    bool GetRaw(uint64_t id, ValueType type, ValueBits* out) const noexcept;
    void RehashGraph() noexcept;

    std::vector<GraphNode> nodes_;
    std::vector<GraphDependency> deps_;
    std::vector<PersistentValue> values_;

    uint64_t graph_hash_ = 0;
    uint64_t generation_ = 0;
};

// Canonical persistent IDs. StableId() is also available for extensions.
namespace StateId {
    uint64_t TokenStep() noexcept;
    uint64_t Position() noexcept;
    uint64_t KvWriteCursor() noexcept;
    uint64_t SequenceId() noexcept;
    uint64_t MaxTokens() noexcept;
    uint64_t Temperature() noexcept;
    uint64_t TopK() noexcept;
    uint64_t TopP() noexcept;
    uint64_t RepeatPenalty() noexcept;
    uint64_t RngState() noexcept;
    uint64_t ActiveQRows() noexcept;
    uint64_t ActiveQaRows() noexcept;
    uint64_t ActiveQkvRows() noexcept;
}

} // namespace rawrxd::runtime
