// ============================================================================
// ExecutionPlanIR.hpp
// ============================================================================
// The canonical execution plan IR that sits between CanonicalModelGraph
// and the target-specific lowering. This is the "mid-level IR" that
// optimization passes operate on before lowering to AVX512/Vulkan/CUDA.
// ============================================================================

#pragma once

#include "UniversalRuntimeBridge.hpp"
#include <vector>
#include <string>
#include <variant>
#include <unordered_map>
#include <cstdint>

namespace RawrXD {

// ============================================================================
// IR Value - a typed reference to a tensor or intermediate result
// ============================================================================
struct IRValue {
    enum class ValueKind : uint8_t {
        InputTensor,      // Model weight/activation
        Intermediate,     // Computed during execution
        Constant,         // Compile-time constant
        KVCache,          // KV cache slot
        ExpertWeight,     // MoE expert weight (lazy-loaded)
    };
    
    uint32_t    id{0};              // Unique value ID
    ValueKind   kind{ValueKind::Intermediate};
    std::string name;               // e.g. "blk.0.attn_q.weight"
    uint32_t    tensorIndex{0};     // Index into CanonicalModelGraph::tensors
    uint32_t    dims[4]{0,0,0,0};
    uint32_t    numDims{0};
    sovereign::TensorDesc::DataType dtype{sovereign::TensorDesc::DataType::F32};
    
    // For expert weights
    uint32_t    expertId{0};
    bool        isExpert{false};
};

// ============================================================================
// IR Operation - a single node in the execution graph
// ============================================================================
struct IROp {
    enum class OpType : uint8_t {
        // Transformer ops
        EmbeddingLookup,
        RMSNorm,
        QKVProjection,
        RoPE,
        SelfAttention,
        AttentionOutput,
        ResidualAdd,
        FFN,                // Dense FFN (gate + up + down)
        MoERoute,            // Expert routing (top-k)
        ExpertFFN,           // Single expert FFN
        ExpertCombine,       // Weighted sum of expert outputs
        FinalNorm,
        LMHead,
        Sampling,
        
        // Memory ops
        LoadTensor,          // Load from tensor database
        LoadExpert,          // Lazy-load expert from NVMe
        EvictExpert,         // Evict expert from cache
        
        // Control flow
        Loop,                // Token generation loop
        Branch,              // Conditional (e.g., early exit)
    };
    
    uint32_t        id{0};
    OpType          type;
    std::string     opName;             // e.g. "blk.0.self_attn"
    uint32_t        layerId{0};          // Transformer layer index
    
    // Inputs/outputs (indices into IRValue list)
    std::vector<uint32_t> inputs;
    std::vector<uint32_t> outputs;
    
    // Attributes (op-specific parameters)
    std::unordered_map<std::string, float>    floatAttrs;
    std::unordered_map<std::string, int32_t>  intAttrs;
    std::unordered_map<std::string, std::string> strAttrs;
    
    // Fusion hints (filled by optimization passes)
    bool            canFuseWithNext{false};
    bool            canFuseWithPrev{false};
    uint32_t        fusionGroupId{0};
    
    // Memory scheduling hints
    enum class MemoryHint : uint8_t {
        None, Keep, Evict, Prefetch, Pin
    } memHint{MemoryHint::None};
    
    // Expert clustering (for MoE)
    uint32_t        expertClusterId{0};
};

// ============================================================================
// Execution Plan IR - the mid-level IR
// ============================================================================
struct ExecutionPlanIR {
    // All values (tensors + intermediates)
    std::vector<IRValue> values;
    std::unordered_map<std::string, uint32_t> valueIndex; // name -> value id
    
    // All operations (in execution order)
    std::vector<IROp> ops;
    
    // Graph structure
    uint32_t    entryValue{0};     // Input token ids
    uint32_t    exitValue{0};      // Output token id
    
    // Metadata
    uint32_t    numLayers{0};
    uint32_t    hiddenSize{0};
    bool        isMoE{false};
    uint32_t    numExperts{0};
    uint32_t    numActiveExperts{0};
    
    // Optimization flags (set by passes)
    bool        fused{false};
    bool        memoryScheduled{false};
    bool        expertsClustered{false};
    bool        constantsFolded{false};
    
    // Value management
    uint32_t    AddValue(const IRValue& v) {
        uint32_t id = static_cast<uint32_t>(values.size());
        IRValue val = v;
        val.id = id;
        values.push_back(val);
        if (!val.name.empty()) valueIndex[val.name] = id;
        return id;
    }
    
    uint32_t    AddOp(const IROp& op) {
        uint32_t id = static_cast<uint32_t>(ops.size());
        IROp o = op;
        o.id = id;
        ops.push_back(o);
        return id;
    }
    
    IRValue*    GetValue(uint32_t id) {
        if (id >= values.size()) return nullptr;
        return &values[id];
    }
    
    IROp*       GetOp(uint32_t id) {
        if (id >= ops.size()) return nullptr;
        return &ops[id];
    }
    
    // Find value by name
    IRValue*    FindValue(const std::string& name) {
        auto it = valueIndex.find(name);
        if (it == valueIndex.end()) return nullptr;
        return &values[it->second];
    }
};

// ============================================================================
// IR Builder - constructs ExecutionPlanIR from CanonicalModelGraph
// ============================================================================
class IRBuilder {
public:
    // Build the full execution plan from a canonical model graph
    static std::unique_ptr<ExecutionPlanIR> Build(const CanonicalModelGraph& graph);
    
private:
    static void BuildTransformerLayer(ExecutionPlanIR& ir, 
                                       const CanonicalModelGraph& graph,
                                       uint32_t layerId);
    static void BuildMoELayer(ExecutionPlanIR& ir,
                              const CanonicalModelGraph& graph,
                              uint32_t layerId);
    static void BuildDenseFFN(ExecutionPlanIR& ir,
                              const CanonicalModelGraph& graph,
                              uint32_t layerId);
    static void BuildSampling(ExecutionPlanIR& ir,
                              const CanonicalModelGraph& graph);
};

} // namespace RawrXD