#pragma once
#include <cstdint>
#include <functional>
#include <stdexcept>
#include <vector>
#include <string>
namespace deep2 {
enum class PlacementMode { SingleGpu, SplitModel, ModelPlusContext, TieredContext };
enum class KvFormat { FP16, INT8 };
struct Geometry { uint32_t layers=0, kv_heads=0, key_dim=0, value_dim=0, mla_latent_dim=0, recurrent_bytes_per_session=0; bool mla=false, recurrent=false; uint64_t max_validated_positions=0; };
struct Capacity { uint64_t bytes_per_token=0, required_bytes=0, usable_bytes=0; bool fits=false; };
struct Placement { PlacementMode mode; uint32_t model_device=0, context_device=4; Capacity context; std::string reason; };
Capacity estimate_kv(const Geometry&, uint64_t positions, KvFormat, uint64_t usable_bytes, uint64_t overhead_bytes);
Placement plan_context(const Geometry&, uint64_t positions, KvFormat, uint64_t model_weight_bytes, uint64_t model_free_bytes, uint64_t context_free_bytes, uint64_t overhead_bytes, uint32_t model_device=0, uint32_t context_device=4);
// Each callback MUST execute real backend work. No simulated success is provided.
struct ContextBackend {
 std::function<void(uint32_t,uint64_t,const void*,uint64_t)> append_kv; // layer,position,packed KV,bytes
 std::function<void(uint32_t,uint64_t,const void*,uint64_t,void*,uint64_t)> attention; // layer,pos,Q,Qbytes,out,outbytes
 std::function<void(uint32_t)> wait_context;
};
class ContextSession {
 Geometry g_; uint64_t position_=0; ContextBackend backend_;
public:
 ContextSession(Geometry g, ContextBackend backend);
 void append(uint32_t layer,uint64_t position,const void* packed,uint64_t bytes);
 void attend(uint32_t layer,uint64_t position,const void* query,uint64_t query_bytes,void* output,uint64_t output_bytes);
 uint64_t position() const {return position_;}
 void advance_token();
};
}
