#pragma once
#include <cstdint>
#include <cstddef>

#ifndef D2_RG_MAX_TENSORS
#define D2_RG_MAX_TENSORS 4096u
#endif
#ifndef D2_RG_MAX_NODES
#define D2_RG_MAX_NODES 1024u
#endif
#ifndef D2_RG_MAX_NODE_INPUTS
#define D2_RG_MAX_NODE_INPUTS 8u
#endif
#ifndef D2_RG_MAX_GPU_SLOTS
#define D2_RG_MAX_GPU_SLOTS 256u
#endif
#ifndef D2_RG_MAX_ACTIONS
#define D2_RG_MAX_ACTIONS 8192u
#endif

namespace d2rg {

enum class Tier : std::uint8_t {
    NONE = 0,
    GPU0 = 1,
    GPU1 = 2,
    RAM  = 3
};

enum class Codec : std::uint8_t {
    UNKNOWN = 0,
    F32,
    F16,
    Q8_0,
    Q4_0,
    Q4_K,
    Q5_K,
    Q6_K,
    Q2_K
};

enum class Op : std::uint16_t {
    NOP = 0,
    EMBEDDING,
    RMS_NORM,
    QKV_PACKED_GEMV,
    ROPE_KV_APPEND,
    ATTENTION,
    OUT_PACKED_GEMV,
    RESIDUAL,
    FFN_GATE_UP_PACKED,
    FFN_ACT,
    FFN_DOWN_PACKED,
    MOE_ROUTER,
    MOE_EXPERT_PACKED,
    FINAL_NORM,
    LM_HEAD_TILED_REDUCE,
    SAMPLE_COMMIT
};

enum TensorFlags : std::uint32_t {
    TF_NONE             = 0,
    TF_WEIGHT           = 1u << 0,
    TF_KV               = 1u << 1,
    TF_ACTIVATION       = 1u << 2,
    TF_PINNED           = 1u << 3,
    TF_PREFER_GPU0      = 1u << 4,
    TF_PREFER_GPU1      = 1u << 5,
    TF_ALLOW_EVICT      = 1u << 6,
    TF_EXACT_RANGE      = 1u << 7,
    TF_PACKED_NATIVE    = 1u << 8
};

struct TensorDesc {
    std::uint32_t id;
    std::uint32_t flags;
    Codec codec;
    std::uint8_t reserved0[3];

    // Exact source range. Deep2 loader owns the file/shard handle.
    std::uint32_t shard_id;
    std::uint32_t reserved1;
    std::uint64_t file_offset;
    std::uint64_t bytes;

    // Logical geometry; interpretation is op/codec specific.
    std::uint32_t dim0;
    std::uint32_t dim1;
    std::uint32_t dim2;
    std::uint32_t dim3;
};

struct NodeDesc {
    std::uint32_t id;
    Op op;
    std::uint16_t input_count;
    std::uint32_t inputs[D2_RG_MAX_NODE_INPUTS];
    std::uint32_t output;
    std::uint32_t aux;
    std::uint32_t flags;
};

struct Capacity {
    std::uint64_t gpu0_bytes;
    std::uint64_t gpu1_bytes;
    std::uint64_t reserve_gpu0_bytes;
    std::uint64_t reserve_gpu1_bytes;
};

struct PackedView {
    std::uint32_t tensor_id;
    Tier tier;
    Codec codec;
    std::uint64_t device_offset;
    std::uint64_t bytes;
    std::uint32_t flags;
};

struct TokenContext {
    std::uint64_t token_index;
    std::uint32_t position;
    std::int32_t input_token;
    std::int32_t output_token;
    std::uint32_t active_gpu_mask;
};

enum class ActionKind : std::uint8_t {
    NONE = 0,
    LOAD_EXACT,
    EVICT,
    DISPATCH,
    TOKEN_SYNC
};

struct Action {
    ActionKind kind;
    Tier tier;
    std::uint16_t reserved;
    std::uint32_t node_id;
    std::uint32_t tensor_id;
};

struct CompileStats {
    std::uint32_t tensor_count;
    std::uint32_t node_count;
    std::uint32_t action_count;
    std::uint32_t pinned_gpu0;
    std::uint32_t pinned_gpu1;
    std::uint64_t pinned_gpu0_bytes;
    std::uint64_t pinned_gpu1_bytes;
    bool zero_token_heap;
    bool exact_range_only;
};

struct RunStats {
    std::uint64_t tokens;
    std::uint64_t dispatches;
    std::uint64_t load_exact_calls;
    std::uint64_t evictions;
    std::uint64_t token_syncs;
    std::uint64_t bytes_loaded_gpu0;
    std::uint64_t bytes_loaded_gpu1;
    std::uint64_t per_token_heap_allocations;
};

using LoadExactFn = bool (*)(
    void* user,
    const TensorDesc* tensor,
    Tier dst,
    std::uint64_t device_offset,
    PackedView* out_view) noexcept;

using EvictFn = bool (*)(
    void* user,
    const PackedView* view) noexcept;

using DispatchFn = bool (*)(
    void* user,
    const NodeDesc* node,
    const PackedView* const* inputs,
    std::uint32_t input_count,
    PackedView* output,
    TokenContext* token) noexcept;

using TokenSyncFn = bool (*)(
    void* user,
    TokenContext* token) noexcept;

struct Backend {
    void* user;
    LoadExactFn load_exact;
    EvictFn evict;
    DispatchFn dispatch;
    TokenSyncFn token_sync;
};

class ResidencyGraph {
public:
    ResidencyGraph() noexcept;

    bool reset() noexcept;
    bool set_capacity(const Capacity& c) noexcept;
    bool bind_backend(const Backend& b) noexcept;

    bool add_tensor(const TensorDesc& t) noexcept;
    bool add_node(const NodeDesc& n) noexcept;

    // Freeze graph topology and create a deterministic, fixed-capacity residency plan.
    // No heap allocation is performed by this class.
    bool compile() noexcept;

    // Execute one autoregressive token using the precompiled graph and residency plan.
    bool run_token(TokenContext* ctx) noexcept;

    const CompileStats& compile_stats() const noexcept { return cstats_; }
    const RunStats& run_stats() const noexcept { return rstats_; }

    const PackedView* view(std::uint32_t tensor_id) const noexcept;

private:
    struct Slot {
        bool used;
        bool pinned;
        Tier tier;
        std::uint32_t tensor_id;
        std::uint64_t offset;
        std::uint64_t bytes;
        std::uint32_t last_use_node;
        PackedView view;
    };

    struct TensorState {
        bool present;
        bool resident;
        TensorDesc desc;
        std::uint32_t first_use;
        std::uint32_t last_use;
        std::uint32_t next_use_cursor;
        std::int32_t slot_index;
    };

    bool plan_tensor_uses() noexcept;
    bool pin_static_working_set() noexcept;
    bool ensure_resident(std::uint32_t tensor_id, std::uint32_t node_index) noexcept;
    bool ensure_output(std::uint32_t tensor_id, Tier preferred) noexcept;
    bool evict_one(Tier tier, std::uint32_t at_node) noexcept;
    bool alloc_slot(Tier tier, std::uint64_t bytes, bool pinned,
                    std::uint32_t tensor_id, std::int32_t* out_slot) noexcept;
    void free_slot(std::int32_t slot) noexcept;
    Tier choose_tier(const TensorDesc& t) const noexcept;
    std::uint64_t tier_capacity(Tier t) const noexcept;
    std::uint64_t tier_used(Tier t) const noexcept;
    std::uint64_t align256(std::uint64_t x) const noexcept;
    std::int32_t find_tensor(std::uint32_t id) const noexcept;
    std::int32_t find_node(std::uint32_t id) const noexcept;

    Capacity cap_{};
    Backend backend_{};
    bool backend_bound_ = false;
    bool compiled_ = false;

    TensorState tensors_[D2_RG_MAX_TENSORS]{};
    NodeDesc nodes_[D2_RG_MAX_NODES]{};
    Slot slots_[D2_RG_MAX_GPU_SLOTS]{};
    Action actions_[D2_RG_MAX_ACTIONS]{};

    std::uint32_t tensor_count_ = 0;
    std::uint32_t node_count_ = 0;
    std::uint32_t action_count_ = 0;

    std::uint64_t used_gpu0_ = 0;
    std::uint64_t used_gpu1_ = 0;

    CompileStats cstats_{};
    RunStats rstats_{};
};

} // namespace d2rg
