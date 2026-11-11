// deep2_dualgpu_forward.cpp -- RAWRXD_MULTI_GPU split-model dual-GPU forward.
// Routes blocks [split, blockCount) to a SECOND Vulkan device (default index 4
// = RX 7800 XT) via Executor::SetBlockVulkanDevice, keeping blocks [0,split) on
// the primary device. Run once WITHOUT --split (single-GPU baseline) and once
// WITH --split, each dumping logits; compare full vocab to prove split-model
// numerical parity. Activations are host-mediated between blocks, so the
// device boundary is implicit; cpu_calls must stay 0 (no silent CPU fallback).
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <vector>

#include "runtime_graph_executor.hpp"
#include "universal_gguf.hpp"
#include "quant_dot_dispatch.hpp"

using namespace RawrXD::Deep2;

static uint32_t ArgmaxOf(const std::vector<float>& lg){
    uint32_t a=0; for(size_t i=1;i<lg.size();++i) if(lg[i]>lg[a]) a=(uint32_t)i; return a;
}
static void Dump(const std::string& dir, size_t pos, const std::vector<float>& lg){
    if(dir.empty()) return; char p[1024];
    std::snprintf(p,sizeof(p),"%s/d2_logits_pos%zu.bin",dir.c_str(),pos);
    FILE* f=fopen(p,"wb"); if(f){ fwrite(lg.data(),sizeof(float),lg.size(),f); fclose(f);} }

int main(int argc, char** argv){
    std::string model, tokensArg="1 185 278 20606 23808 7936 14336 28416", dump;
    size_t decode_n=1; long split=-1, ctx_dev=4; bool prefetch=false;
    for(int i=1;i<argc;++i){ std::string a=argv[i];
        if(a=="--model"&&i+1<argc) model=argv[++i];
        else if(a=="--tokens"&&i+1<argc) tokensArg=argv[++i];
        else if(a=="--decode"&&i+1<argc) decode_n=(size_t)strtoull(argv[++i],0,10);
        else if(a=="--split"&&i+1<argc) split=strtol(argv[++i],0,10);
        else if(a=="--ctx-dev"&&i+1<argc) ctx_dev=strtol(argv[++i],0,10);
        else if(a=="--prefetch") prefetch=true;
        else if(a=="--dump"&&i+1<argc) dump=argv[++i];
        else { std::printf("unknown %s\n",a.c_str()); return 1; } }

    const Universal::IngestReport& rep = Universal::Ingest(model,false);
    if(!rep.ok){ std::printf("INGEST_FAIL: %s\n",rep.error.c_str()); return 1; }
    const uint32_t blocks=(uint32_t)rep.spec.block_count;

    RuntimeGraph::Executor ex; ex.SetForceCpu(false);
    if (prefetch) { ex.SetStrataExpertTracking(true); ex.SetStrataExpertPrefetch(true); }
    if(!ex.Bind(rep)){ std::printf("BIND_FAIL: %s\n",ex.Stats().error.c_str()); return 1; }

    std::vector<uint32_t> tokens; { const char* p=tokensArg.c_str(); char* e=nullptr;
        for(long v=strtol(p,&e,10); e!=p; v=strtol(p,&e,10)){ if(v<0)break; tokens.push_back((uint32_t)v); p=e; while(*p==' '||*p==',')++p; if(!*p)break; } }

    // Split routing: blocks [split, blockCount) -> ctx device.
    if (split >= 0 && (uint32_t)split < blocks) {
        for (uint32_t b=(uint32_t)split; b<blocks; ++b) RuntimeGraph::SetBlockVulkanDevice(b, (uint32_t)ctx_dev);
        std::printf("SPLIT blocks [%ld,%u) -> ctx device %ld ; blocks [0,%ld) -> primary\n", split, blocks, ctx_dev, split);
    } else {
        std::printf("SINGLE-GPU baseline (blocks=%u, all primary device)\n", blocks);
    }
    if(!dump.empty()) std::printf("dump dir=%s\n", dump.c_str());

    for(size_t i=0;i<tokens.size();++i){ if(!ex.ExecuteToken(tokens[i],i)){ std::printf("PREFILL_FAIL %s\n",ex.LastError().c_str()); return 2;} Dump(dump,i,ex.Logits()); }
    std::vector<uint32_t> gen; uint32_t t=ArgmaxOf(ex.Logits()); gen.push_back(t);
    for(size_t i=1;i<decode_n;++i){ size_t pos=tokens.size()+i-1;
        if(!ex.ExecuteToken(gen.back(),pos)){ std::printf("DECODE_FAIL %s\n",ex.LastError().c_str()); return 2;} 
        gen.push_back(ArgmaxOf(ex.Logits())); Dump(dump,tokens.size()+i-1,ex.Logits()); }

    const auto& st=ex.Stats();
    std::printf("GENSTREAM:"); for(uint32_t g:gen) std::printf(" %u",g); std::printf("\n");
    std::printf("RESULT gpu_calls=%llu cpu_calls=%llu fallback=%s nonfinite=%llu finite=%s\n",
        (unsigned long long)st.gpu_calls,(unsigned long long)st.cpu_calls,
        st.fallback_reason.empty()?"<none>":st.fallback_reason.c_str(),
        (unsigned long long)ex.NonFiniteLogits(), (ex.NonFiniteLogits()==0)?"yes":"NO");
    // Per-device dispatch proof: primary (default) vs the secondary content GPU.
    {
        QuantDot::CacheStats p = QuantDot::GetCacheStats();
        std::printf("DEVICE_DISPATCH primary submits=%llu weight_misses=%llu evictions=%llu upload=%.1f MiB live=%.1f MiB\n",
            (unsigned long long)p.submits,(unsigned long long)p.misses,(unsigned long long)p.evictions,
            p.upload_bytes/1048576.0, (double)p.device_bytes_live/1048576.0);
        bool split_active = (split >= 0 && (uint32_t)split < blocks);
        if (split_active) {
            QuantDot::CacheStats s = QuantDot::GetCacheStatsOn((int32_t)ctx_dev);
            std::printf("DEVICE_DISPATCH secondary(dev %ld) submits=%llu weight_misses=%llu evictions=%llu prefetches=%llu prefetch_hits=%llu upload=%.1f MiB live=%.1f MiB\n",
                ctx_dev,(unsigned long long)s.submits,(unsigned long long)s.misses,
                (unsigned long long)s.evictions,(unsigned long long)s.prefetches,
                (unsigned long long)s.prefetch_hits,
                s.upload_bytes/1048576.0, (double)s.device_bytes_live/1048576.0);
        }
    }
    std::printf("VERDICT=%s\n", (st.cpu_calls==0 && ex.NonFiniteLogits()==0) ? "PASS" : "FAIL");
    return 0;
}
