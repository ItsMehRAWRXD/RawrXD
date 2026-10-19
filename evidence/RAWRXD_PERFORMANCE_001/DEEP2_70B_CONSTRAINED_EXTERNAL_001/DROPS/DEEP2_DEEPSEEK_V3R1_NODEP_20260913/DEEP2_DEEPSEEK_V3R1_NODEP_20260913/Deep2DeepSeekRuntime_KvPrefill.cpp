#include "Deep2DeepSeekRuntime.hpp"

namespace Deep2 { namespace dsv3 {
KvPlan PlanKv(uint32_t context,uint32_t hot,uint32_t warm){
    KvPlan p{}; p.context=context; p.hotTokens=context<hot?context:hot;
    uint32_t rem=context-p.hotTokens; p.warmTokens=rem<warm?rem:warm;
    p.hotTier=TIER_VRAM; p.warmTier=TIER_RAM; p.coldTier=TIER_MMAP; return p;
}
PrefillPlan PlanPrefill(const State&s,uint32_t tokens){
    PrefillPlan p{}; p.totalTokens=tokens; p.chunkTokens=s.cfg.prefillChunk?s.cfg.prefillChunk:512u;
    if(p.chunkTokens>tokens&&tokens)p.chunkTokens=tokens;
    p.chunks=p.chunkTokens?(tokens+p.chunkTokens-1u)/p.chunkTokens:0; return p;
}
}} 
