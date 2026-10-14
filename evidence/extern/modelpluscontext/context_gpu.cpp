#include "context_gpu.hpp"
#include <limits>
namespace deep2 {
static uint64_t checked_mul(uint64_t a,uint64_t b){ if(a && b>UINT64_MAX/a) throw std::overflow_error("KV capacity overflow"); return a*b; }
static uint64_t checked_add(uint64_t a,uint64_t b){ if(b>UINT64_MAX-a) throw std::overflow_error("KV capacity overflow"); return a+b; }
Capacity estimate_kv(const Geometry& g,uint64_t positions,KvFormat fmt,uint64_t usable,uint64_t overhead){
 if(!g.layers || !positions) throw std::invalid_argument("layers/positions must be nonzero");
 if(g.max_validated_positions && positions>g.max_validated_positions) throw std::invalid_argument("requested context exceeds validated model context");
 if(g.recurrent) throw std::invalid_argument("recurrent state requires architecture-specific planner");
 uint64_t scalars=0;
 if(g.mla){ if(!g.mla_latent_dim) throw std::invalid_argument("MLA geometry absent"); scalars=g.mla_latent_dim; }
 else { if(!g.kv_heads || !g.key_dim || !g.value_dim) throw std::invalid_argument("KV geometry absent"); scalars=checked_mul(g.kv_heads,checked_add(g.key_dim,g.value_dim)); }
 uint64_t bps=fmt==KvFormat::FP16?2:1;
 Capacity c; c.bytes_per_token=checked_mul(checked_mul(g.layers,scalars),bps);
 c.required_bytes=checked_add(checked_mul(c.bytes_per_token,positions),overhead);
 c.usable_bytes=usable;c.fits=c.required_bytes<=usable;return c;
}
Placement plan_context(const Geometry& g,uint64_t positions,KvFormat fmt,uint64_t weights,uint64_t model_free,uint64_t context_free,uint64_t overhead,uint32_t model_device,uint32_t context_device){
 if(model_device==context_device) throw std::invalid_argument("devices must differ");
 Placement p; p.model_device=model_device;p.context_device=context_device;
 p.context=estimate_kv(g,positions,fmt,context_free,overhead);
 if(weights>model_free){p.mode=PlacementMode::SplitModel;p.reason="model weights do not fit model GPU; split-model integration required";}
 else if(p.context.fits){p.mode=PlacementMode::ModelPlusContext;p.reason="model fits primary GPU and KV fits context GPU";}
 else {p.mode=PlacementMode::TieredContext;p.reason="context exceeds dedicated GPU; RAM/NVMe paging required";}
 return p;
}
ContextSession::ContextSession(Geometry g,ContextBackend b):g_(g),backend_(std::move(b)){
 if(!g_.layers || !backend_.append_kv || !backend_.attention || !backend_.wait_context) throw std::invalid_argument("incomplete real context backend");
}
void ContextSession::append(uint32_t layer,uint64_t pos,const void* data,uint64_t bytes){
 if(layer>=g_.layers || pos!=position_ || !data || !bytes) throw std::invalid_argument("invalid KV append");
 backend_.append_kv(layer,pos,data,bytes);
}
void ContextSession::attend(uint32_t layer,uint64_t pos,const void* q,uint64_t qb,void* out,uint64_t ob){
 if(layer>=g_.layers || pos!=position_ || !q || !qb || !out || !ob) throw std::invalid_argument("invalid remote attention");
 backend_.wait_context(layer); backend_.attention(layer,pos,q,qb,out,ob); backend_.wait_context(layer);
}
void ContextSession::advance_token(){if(g_.max_validated_positions && position_+1>=g_.max_validated_positions) throw std::out_of_range("context limit"); ++position_;}
}
