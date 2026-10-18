#include "Deep2B66RuntimeMeta.hpp"
#include <algorithm>

namespace Deep2 {

static uint32_t u32get(const B66MetadataSource& s, const char* key, uint32_t def=0) {
    auto it=s.u64.find(key);
    return it==s.u64.end()?def:static_cast<uint32_t>(it->second);
}
static double fget(const B66MetadataSource& s, const char* key, double def=0.0) {
    auto it=s.f64.find(key);
    return it==s.f64.end()?def:it->second;
}
static std::string sget(const B66MetadataSource& s, const char* key) {
    auto it=s.str.find(key);
    return it==s.str.end()?std::string():it->second;
}

B66Result B66RuntimeMetaBinder::bind(const B66MetadataSource& s) noexcept {
    B66Result r{};
    auto& m=r.meta;
    m.architecture=sget(s,"general.architecture");
    if(m.architecture.empty()) return {false,"ARCHITECTURE_MISSING",{}};

    m.totalParamsB=fget(s,"deep2.total_params_b");
    m.activeParamsB=fget(s,"deep2.active_params_b");
    m.layers=u32get(s,"block_count",u32get(s,"llm.block_count"));
    m.hidden=u32get(s,"embedding_length",u32get(s,"llm.embedding_length"));
    m.heads=u32get(s,"attention.head_count");
    m.kvHeads=u32get(s,"attention.head_count_kv");
    m.headDim=u32get(s,"attention.key_length");
    if(!m.headDim && m.heads && m.hidden) m.headDim=m.hidden/m.heads;
    m.intermediate=u32get(s,"feed_forward_length");
    m.experts=u32get(s,"expert_count");
    m.expertsPerToken=u32get(s,"expert_used_count");
    m.sharedExperts=u32get(s,"expert_shared_count");
    m.context=u32get(s,"context_length");
    m.qLoraRank=u32get(s,"attention.q_lora_rank");
    m.kvLoraRank=u32get(s,"attention.kv_lora_rank");
    m.ropeDim=u32get(s,"rope.dimension_count");

    const auto arch=m.architecture;
    m.useMLA = m.kvLoraRank>0 ||
               arch.find("deepseek")!=std::string::npos ||
               arch.find("kimi")!=std::string::npos;
    m.useSSM = arch.find("mamba")!=std::string::npos ||
               arch.find("nemotron")!=std::string::npos ||
               u32get(s,"ssm.state_size")>0;
    m.useSlidingWindow = u32get(s,"attention.sliding_window")>0;
    m.useHybridLinearAttention =
        arch.find("qwen3next")!=std::string::npos ||
        u32get(s,"attention.linear_layer_count")>0;

    if(!m.layers) return {false,"LAYERS_MISSING",{}};
    if(!m.hidden) return {false,"HIDDEN_MISSING",{}};
    if(!m.context) return {false,"CONTEXT_MISSING",{}};
    if(m.experts && !m.expertsPerToken) return {false,"MOE_TOPK_MISSING",{}};

    r.pass=true;
    r.failure="PASS";
    return r;
}

} // namespace Deep2
