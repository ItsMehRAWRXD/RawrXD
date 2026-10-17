#pragma once
// Deep2 Bolt pipeline contract — C++20, standard library only.
// Adapters must connect to the existing, validated Deep2 GGUF and tokenizer implementations.
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <functional>
#include <limits>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace deep2::bolt {
struct Error : std::runtime_error { using std::runtime_error::runtime_error; };
enum class LayerKind { SSM, Attention };
enum class Quant { F32=0, Q8_0=8, IQ2_XXS=16, NVFP4=40 };
struct TensorDesc { std::string name; Quant type; std::vector<uint64_t> dims; uint64_t offset{}, bytes{}; };
struct LayerDesc { uint32_t index{}; LayerKind kind{}; uint32_t router_width{}; bool has_moe{}; };
struct ModelDesc { uint32_t layers{}, hidden{}, vocab{}; uint64_t file_bytes{}; std::vector<TensorDesc> tensors; std::vector<LayerDesc> plan; };

inline uint64_t checked_mul(uint64_t a, uint64_t b) {
    if (b && a > std::numeric_limits<uint64_t>::max()/b) throw Error("tensor dimension overflow");
    return a*b;
}
inline uint64_t checked_add(uint64_t a, uint64_t b) {
    if (a > std::numeric_limits<uint64_t>::max()-b) throw Error("tensor offset overflow");
    return a+b;
}
inline uint64_t tensor_elements(const TensorDesc& t) {
    if (t.dims.empty()) throw Error("scalar/empty tensor dimensions require explicit handling: " + t.name);
    uint64_t n=1; for(auto d:t.dims) { if(!d) throw Error("zero tensor dimension: "+t.name); n=checked_mul(n,d); }
    return n;
}
inline void validate_inventory(const ModelDesc& m) {
    if(m.layers!=88 || m.hidden!=4096 || m.vocab!=131072) throw Error("unexpected Bolt metadata");
    if(m.tensors.size()!=843 || m.plan.size()!=m.layers) throw Error("incomplete tensor inventory or layer plan");
    std::unordered_map<std::string,bool> seen;
    uint32_t counts[4]{};
    std::vector<std::pair<uint64_t,uint64_t>> ranges;
    for(const auto& t:m.tensors) {
        if(!seen.emplace(t.name,true).second) throw Error("duplicate tensor: "+t.name);
        const uint64_t n=tensor_elements(t);
        uint64_t expected=0;
        switch(t.type) {
        case Quant::F32: expected=checked_mul(n,4); ++counts[0]; break;
        case Quant::Q8_0: expected=checked_mul((n+31)/32,34); ++counts[1]; break;
        case Quant::IQ2_XXS: expected=checked_mul((n+255)/256,66); ++counts[2]; break;
        case Quant::NVFP4:
            // NVFP4 serialization can include auxiliary scales. Verify through the actual
            // loader's authoritative type geometry; don't guess 36 bytes here.
            // Partial blocks in the final row are padded per GGUF spec.
            if(!t.bytes) throw Error("NVFP4 byte extent not supplied: "+t.name);
            ++counts[3]; break;
        default: throw Error("unsupported tensor type: "+t.name);
        }
        if(expected && t.bytes!=expected) throw Error("incorrect tensor byte extent: "+t.name);
        const auto end=checked_add(t.offset,t.bytes);
        if(end>m.file_bytes) throw Error("tensor outside GGUF data: "+t.name);
        ranges.emplace_back(t.offset,end);
    }
    std::sort(ranges.begin(),ranges.end());
    for(size_t i=1;i<ranges.size();++i)
        if(ranges[i].first<ranges[i-1].second) throw Error("overlapping tensor byte ranges");
    if(counts[0]!=489 || counts[1]!=114 || counts[2]!=160 || counts[3]!=80)
        throw Error("Bolt tensor type counts mismatch");
    for(uint32_t i=0;i<m.layers;++i) {
        const auto& l=m.plan[i];
        if(l.index!=i) throw Error("non-contiguous layer plan");
        if(l.has_moe && !l.router_width) throw Error("MoE router width missing");
    }
}

struct DecodeState {
    uint64_t position{};
    std::vector<std::vector<float>> ssm_state;
    std::vector<std::vector<float>> conv_state;
    std::vector<std::vector<float>> kv_keys, kv_values;
};

// Each callback must be a real implementation, not a metadata-only stub.
// The existing Deep2 backend owns model tensors and operator-specific state shapes.
struct Operators {
    std::function<void(const ModelDesc&,DecodeState&)> initialize_state;
    std::function<void(uint32_t,std::span<float>,DecodeState&)> ssm_layer;
    std::function<void(uint32_t,std::span<float>,DecodeState&)> attention_layer;
    std::function<void(uint32_t,std::span<float>,DecodeState&)> moe_layer;
    std::function<void(uint32_t,std::span<const float>,std::span<float>)> output_logits;
};

class Pipeline {
    ModelDesc model_;
    Operators ops_;
    DecodeState state_;
    std::vector<float> hidden_, logits_;
    bool initialized_=false;
public:
    Pipeline(ModelDesc model, Operators ops) : model_(std::move(model)), ops_(std::move(ops)),
      hidden_(model_.hidden), logits_(model_.vocab) {
        validate_inventory(model_);
        if(!ops_.initialize_state || !ops_.ssm_layer || !ops_.attention_layer ||
           !ops_.moe_layer || !ops_.output_logits)
            throw Error("missing Bolt operator implementation");
    }
    void reset() {
        state_={}; ops_.initialize_state(model_,state_); initialized_=true;
    }
    // `embedding` must be the genuine model embedding for this token.
    std::span<const float> forward(std::span<const float> embedding) {
        if(!initialized_) throw Error("call reset() before forward()");
        if(embedding.size()!=hidden_.size()) throw Error("embedding width mismatch");
        std::copy(embedding.begin(),embedding.end(),hidden_.begin());
        for(const auto& layer:model_.plan) {
            if(layer.kind==LayerKind::SSM) ops_.ssm_layer(layer.index,hidden_,state_);
            else ops_.attention_layer(layer.index,hidden_,state_);
            if(layer.has_moe) ops_.moe_layer(layer.index,hidden_,state_);
            for(float v:hidden_) if(!std::isfinite(v)) throw Error("nonfinite hidden state at layer "+std::to_string(layer.index));
        }
        ops_.output_logits(state_.position,hidden_,logits_);
        for(float v:logits_) if(!std::isfinite(v)) throw Error("nonfinite logits");
        ++state_.position;
        return logits_;
    }
    uint64_t position() const {return state_.position;}
};

inline uint32_t greedy(std::span<const float> logits) {
    if(logits.empty()) throw Error("empty logits");
    for(float v:logits) if(!std::isfinite(v)) throw Error("nonfinite sampler input");
    return static_cast<uint32_t>(std::max_element(logits.begin(),logits.end())-logits.begin());
}
} // namespace deep2::bolt
