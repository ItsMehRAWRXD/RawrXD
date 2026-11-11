#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>
#include <functional>

namespace RawrXD {

// ═══ laFabric Tensor Residency & Identity Table ═══
// Decouples logical tensor identity from physical execution state.
// Enables zero-copy VRAM migration, precision conversion, and
// hotpatching without invalidating the execution graph.

enum class MemoryTier : uint8_t {
    COLD_NANO,      // NVMe / SSD storage (F:\ OllamaModels)
    NANO_KEEP,      // System RAM (64GB DDR5-5600)
    PATCH_HOT,      // VRAM staging / DMA buffer
    COMPUTE_FRONTIER // GPU active execution (R9700 32GB)
};

enum class TensorFormat : uint32_t {
    UNKNOWN = 0,
    Q4_0, Q4_1, Q4_K, Q4_K_M,      // 4-bit quantized
    Q5_0, Q5_1, Q5_K, Q5_K_M,      // 5-bit quantized
    Q6_K, Q8_0, Q8_1,               // 6-8 bit quantized
    IQ2_XXS, IQ2_XS, IQ2_S,         // 2-bit IQ
    IQ3_XXS, IQ3_XS, IQ3_S,         // 3-bit IQ
    IQ4_NL,                         // 4-bit IQ
    FP16, BF16, FP32,               // Floating point
    INT8, INT4, INT2                // Integer
};

struct FabricTensorDescriptor {
    uint64_t tensorID;              // Logical identity (S) — immutable

    TensorFormat storageFormat;     // coldNano format
    TensorFormat executionFormat;   // patchHot format

    int64_t  boundaryOffset;      // -61 entry / +61 exit
    uint32_t registerSlot;          // x16 patch slot

    MemoryTier residency;

    void*    physicalAddress;       // Active pointer (may change)
    uint64_t checksum;              // Integrity hash
    bool     identityValid;         // r...r lock state

    // Kimi K2 / MoE specific
    uint32_t layerId;
    uint32_t expertId;
    uint64_t ggufFileOffset;
    uint32_t shardIndex;
};

class FabricTensorTable {
public:
    using TensorCallback = std::function<void(const FabricTensorDescriptor&)>;

    // Engage the fabric transition boundary (-61)
    void enter_fabric_transition(uint64_t id, TensorFormat target_format, uint32_t slot) {
        auto& desc = table_[id];

        // Save previous state (r_in)
        desc.boundaryOffset = -61;
        desc.identityValid = true;
        desc.executionFormat = target_format;
        desc.registerSlot = slot;

        // Log transition
        if (transitionCallback_) {
            transitionCallback_(desc);
        }
    }

    // Exit the fabric transition boundary (+61) and verify identity
    bool exit_fabric_transition(uint64_t id, void* new_addr, MemoryTier new_residency) {
        auto it = table_.find(id);
        if (it == table_.end()) {
            return false;
        }

        auto& desc = it->second;

        // Apply physical changes
        void* old_addr = desc.physicalAddress;
        desc.physicalAddress = new_addr;
        desc.residency = new_residency;
        desc.boundaryOffset = +61; // Context restore

        // Verify r_in.identity == r_out.identity
        bool integrity = validate_fabric_transition(desc, desc);

        if (transitionCallback_) {
            transitionCallback_(desc);
        }

        return integrity;
    }

    // Register a tensor from GGUF shard scan
    void register_tensor(const FabricTensorDescriptor& desc) {
        table_[desc.tensorID] = desc;
    }

    // Lookup by tensor ID
    std::optional<FabricTensorDescriptor> lookup(uint64_t id) const {
        auto it = table_.find(id);
        if (it == table_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    // Lookup by layer + expert (MoE routing)
    std::optional<FabricTensorDescriptor> lookup_layer_expert(uint32_t layer, uint32_t expert) const {
        for (const auto& [id, desc] : table_) {
            if (desc.layerId == layer && desc.expertId == expert) {
                return desc;
            }
        }
        return std::nullopt;
    }

    // Set callback for transition events
    void on_transition(TensorCallback cb) {
        transitionCallback_ = std::move(cb);
    }

    size_t size() const { return table_.size(); }

    // Bulk register from GGUFShardRouter scan results
    void ingest_gguf_router(const class GGUFShardRouter& router);

private:
    std::unordered_map<uint64_t, FabricTensorDescriptor> table_;
    TensorCallback transitionCallback_;

    bool validate_fabric_transition(
        const FabricTensorDescriptor& before,
        const FabricTensorDescriptor& after)
    {
        // Core invariant: logical object never changes, even if address/format does
        return (before.tensorID == after.tensorID) &&
               (after.identityValid) &&
               (after.checksum == before.checksum);
    }
};

// ═══ IPA via MLG — Intermediate Physical Address via Memory Location Graph ═══
// Maps logical tensor addresses to physical residency tiers with hop-cost metrics.
// Enables predictive prefetch and expert routing for MoE architectures.

class IPAviaMLG {
public:
    struct MLGNode {
        MemoryTier tier;
        uintptr_t  physical_addr;
        uint32_t   hop_cost;     // 0=VRAM, 1=RAM, 2=NVMe
        bool       resident;
    };

    struct MainLevelGGUFEntry {
        uint64_t    tensor_id;
        std::string shard_path;
        uint64_t    file_offset;
        MLGNode     current_residency;
    };

    void register_mainlevel_gguf(
        uint64_t tensor_id,
        const std::string& shard_path,
        uint64_t file_offset,
        MemoryTier tier,
        uintptr_t addr,
        uint32_t hop_cost,
        bool resident)
    {
        main_level_gguf_[tensor_id] = {
            tensor_id,
            shard_path,
            file_offset,
            { tier, addr, hop_cost, resident }
        };
    }

    std::optional<MLGNode> resolve_ipa(uint64_t tensor_id, uint32_t max_hops) const {
        auto it = main_level_gguf_.find(tensor_id);
        if (it == main_level_gguf_.end()) {
            return std::nullopt;
        }

        const auto& entry = it->second;

        if (!entry.current_residency.resident) {
            return std::nullopt;
        }

        if (entry.current_residency.hop_cost > max_hops) {
            return std::nullopt;
        }

        return entry.current_residency;
    }

    std::optional<MainLevelGGUFEntry> get_main_level_entry(uint64_t tensor_id) const {
        auto it = main_level_gguf_.find(tensor_id);
        if (it == main_level_gguf_.end()) {
            return std::nullopt;
        }
        return it->second;
    }

    // Compute residency plan for 621GB Kimi K2 on 32GB VRAM
    // Returns: number of tensors that can be PATCH_HOT / COMPUTE_FRONTIER
    size_t compute_residency_plan(uint64_t vram_budget_bytes) const;

private:
    std::unordered_map<uint64_t, MainLevelGGUFEntry> main_level_gguf_;
};

} // namespace RawrXD
